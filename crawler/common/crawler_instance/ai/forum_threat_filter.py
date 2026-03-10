from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class ThreatDecision:
    keep: bool
    label: str
    score: float
    reasons: List[str]
    indicators: Dict[str, List[str]]


class ForumThreatFilter:
    """
    Free + fast + accurate-ish (no training):
    - keyword gate
    - SBERT similarity (SentenceTransformers all-MiniLM-L6-v2)

    If sentence-transformers is not installed, it will gracefully fallback to keyword-only mode.
    """

    MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

    # High-signal categories for TI
    LABELS = [
        "DATA_LEAK",
        "ACCESS_SALE",
        "MALWARE_LOGS",
        "CARDING",
        "SPAM_ADS",
        "RESTRICTED",
        "OTHER",
    ]

    # Keyword gates (fast)
    HIGH_RISK_KEYWORDS = {
        "DATA_LEAK": [
            "fullz", "ssn", "dob", "passport", "national id", "id card",
            "database", "db", "dump", "leak", "breach", "records", "pii",
            "csv", "sql", "mongodb", "elasticsearch", "telegram user database",
            "gsm", "iban", "credit records", "urssaf", "cic.gov", "registry",
            "millions", "m lines", "100m", "50m", "1m", "10m"
        ],
        "ACCESS_SALE": [
            "rdp", "vpn", "panel", "shell", "cpanel", "ssh", "access",
            "initial access", "citrix", "fortigate", "pulse secure", "zimbra",
            "admin access", "corporate access"
        ],
        "MALWARE_LOGS": [
            "stealer", "logs", "redline", "raccoon", "lumma", "vidar",
            "combo", "combos", "config", "botnet", "infostealer"
        ],
        "CARDING": [
            "cvv", "cc", "credit card", "dumps", "track1", "track2",
            "bank logs", "atm", "swift"
        ],
        "SPAM_ADS": [
            "join my telegram", "exclusive news", "signal", "earn money",
            "passive income", "marketing", "affiliate"
        ],
    }

    # Restricted content patterns (login wall)
    RESTRICTED_PATTERNS = [
        "you need to sign in",
        "register to view",
        "log in to view",
        "sign in or register",
    ]

    # IOC-ish regex
    RE_TELEGRAM = re.compile(r"(?:t\.me/|telegram\.me/|@)([A-Za-z0-9_]{4,})", re.IGNORECASE)
    RE_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.IGNORECASE)
    RE_DISCORD = re.compile(r"(?:discord\.gg/|discord\.com/invite/)([A-Za-z0-9]+)", re.IGNORECASE)
    RE_URL = re.compile(r"https?://[^\s<>\]\)\"']+", re.IGNORECASE)

    def __init__(self, use_embeddings: bool = True):
        self.use_embeddings = use_embeddings
        self._embedder = None
        self._ref_embeds = None
        self._ref_texts = None

        if self.use_embeddings:
            self._try_load_embedder()

    # -----------------------------
    # Embeddings setup
    # -----------------------------
    def _try_load_embedder(self):
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore

            self._embedder = SentenceTransformer(self.MODEL_NAME)

            # Reference intents (anchors)
            self._ref_texts = {
                "DATA_LEAK": [
                    "selling leaked database", "personal data leak for sale", "fullz ssn dob records", "national registry dump",
                    "telegram user database dump", "credit records leak", "identity database for sale"
                ],
                "ACCESS_SALE": [
                    "selling rdp access", "vpn access for sale", "admin panel access", "corporate network access",
                    "initial access broker post"
                ],
                "MALWARE_LOGS": [
                    "selling stealer logs", "infostealer logs for sale", "combo list leak", "malware logs database"
                ],
                "CARDING": [
                    "selling credit card dumps", "cvv shop", "track1 track2 dumps", "bank logs for sale"
                ],
                "SPAM_ADS": [
                    "generic advertisement", "spam promotion post", "telegram channel promotion", "crypto news spam"
                ],
            }

            # Precompute embeds for speed
            self._ref_embeds = {}
            for label, texts in self._ref_texts.items():
                self._ref_embeds[label] = self._embedder.encode(texts, normalize_embeddings=True)

        except Exception:
            # fallback keyword-only
            self._embedder = None
            self._ref_embeds = None
            self._ref_texts = None
            self.use_embeddings = False

    # -----------------------------
    # Public API
    # -----------------------------
    def decide(self, title: str, content: str, category: str = "") -> ThreatDecision:
        text = f"{title}\n{content}".strip().lower()

        indicators = self._extract_indicators(text)

        # 1) Restricted wall
        if any(p in text for p in self.RESTRICTED_PATTERNS):
            return ThreatDecision(
                keep=False,
                label="RESTRICTED",
                score=0.0,
                reasons=["login_wall"],
                indicators=indicators,
            )

        # 2) Keyword gate scoring
        kw_label, kw_score, kw_reasons = self._keyword_score(text)

        # 3) Embedding score (optional)
        emb_label, emb_score = ("OTHER", 0.0)
        if self.use_embeddings and self._embedder is not None and self._ref_embeds is not None:
            emb_label, emb_score = self._embedding_score(text)

        # 4) Fuse decision
        # Simple but effective fusion:
        # - If keyword score is high => keep
        # - else if embedding score is high => keep
        # - else drop spam/low-signal
        final_label, final_score, reasons = self._fuse(kw_label, kw_score, kw_reasons, emb_label, emb_score)

        keep = final_label in {"DATA_LEAK", "ACCESS_SALE", "MALWARE_LOGS", "CARDING"} and final_score >= 0.55
        # allow borderline keeps if many IOCs exist
        if not keep:
            ioc_count = sum(len(v) for v in indicators.values())
            if final_label in {"DATA_LEAK", "ACCESS_SALE"} and ioc_count >= 2 and final_score >= 0.45:
                keep = True
                reasons.append("ioc_boost")

        # Category hint (marketplace tends to be more sale-y)
        if not keep and category.lower() == "marketplace" and final_score >= 0.50 and final_label != "SPAM_ADS":
            keep = True
            reasons.append("marketplace_hint")

        return ThreatDecision(
            keep=keep,
            label=final_label,
            score=float(final_score),
            reasons=reasons,
            indicators=indicators,
        )

    # -----------------------------
    # Keyword scoring
    # -----------------------------
    def _keyword_score(self, text: str) -> Tuple[str, float, List[str]]:
        best_label = "OTHER"
        best_hits = 0
        reasons: List[str] = []

        for label, kws in self.HIGH_RISK_KEYWORDS.items():
            hits = 0
            hit_terms = []
            for kw in kws:
                if kw in text:
                    hits += 1
                    hit_terms.append(kw)
            if hits > best_hits:
                best_hits = hits
                best_label = label
                reasons = [f"kw:{t}" for t in hit_terms[:10]]

        # Convert hits -> score
        # 0 hits: 0.0
        # 1-2 hits: 0.45
        # 3-4 hits: 0.60
        # 5+ hits: 0.75
        if best_hits == 0:
            score = 0.0
        elif best_hits <= 2:
            score = 0.45
        elif best_hits <= 4:
            score = 0.60
        else:
            score = 0.75

        return best_label, score, reasons

    # -----------------------------
    # Embedding scoring
    # -----------------------------
    def _embedding_score(self, text: str) -> Tuple[str, float]:
        # encode once
        q = self._embedder.encode([text], normalize_embeddings=True)[0]

        best_label = "OTHER"
        best_score = 0.0

        # cosine similarity since normalized
        for label, ref_mat in self._ref_embeds.items():
            # compute max dot product
            # ref_mat: shape (n, d)
            # q: (d,)
            # manual dot for speed (no numpy dependency required; sentence-transformers returns numpy array normally)
            try:
                # if numpy exists, this will be fast
                import numpy as np  # type: ignore

                sims = np.dot(ref_mat, q)
                s = float(sims.max())
            except Exception:
                # pure python fallback
                s = 0.0
                for r in ref_mat:
                    dot = 0.0
                    for i in range(len(r)):
                        dot += float(r[i]) * float(q[i])
                    if dot > s:
                        s = dot

            if s > best_score:
                best_score = s
                best_label = label

        return best_label, best_score

    # -----------------------------
    # Fusion logic
    # -----------------------------
    def _fuse(
        self,
        kw_label: str,
        kw_score: float,
        kw_reasons: List[str],
        emb_label: str,
        emb_score: float,
    ) -> Tuple[str, float, List[str]]:
        reasons = []

        # If keywords are strong, trust them
        if kw_score >= 0.60:
            reasons.extend(kw_reasons)
            if emb_score > 0:
                reasons.append(f"emb:{emb_label}:{emb_score:.2f}")
            return kw_label, max(kw_score, emb_score), reasons

        # Else trust embeddings if high
        if emb_score >= 0.60:
            reasons.append(f"emb:{emb_label}:{emb_score:.2f}")
            if kw_score > 0:
                reasons.extend(kw_reasons)
            return emb_label, max(kw_score, emb_score), reasons

        # Else if spam signals
        if kw_label == "SPAM_ADS":
            reasons.extend(kw_reasons)
            if emb_score > 0:
                reasons.append(f"emb:{emb_label}:{emb_score:.2f}")
            return "SPAM_ADS", max(kw_score, emb_score), reasons

        # Default
        if kw_score > 0:
            reasons.extend(kw_reasons)
        if emb_score > 0:
            reasons.append(f"emb:{emb_label}:{emb_score:.2f}")
        return (emb_label if emb_score > kw_score else kw_label), max(kw_score, emb_score), reasons

    # -----------------------------
    # Indicator extraction
    # -----------------------------
    def _extract_indicators(self, text: str) -> Dict[str, List[str]]:
        tg = []
        for m in self.RE_TELEGRAM.finditer(text):
            h = m.group(1)
            if h and h not in tg:
                tg.append(h)

        emails = []
        for e in self.RE_EMAIL.findall(text):
            if e and e not in emails:
                emails.append(e)

        discord = []
        for m in self.RE_DISCORD.finditer(text):
            code = m.group(1)
            if code and code not in discord:
                discord.append(code)

        urls = []
        for u in self.RE_URL.findall(text):
            if u and u not in urls:
                urls.append(u)

        return {
            "telegram": tg[:50],
            "emails": emails[:50],
            "discord_invites": discord[:50],
            "urls": urls[:200],
        }
