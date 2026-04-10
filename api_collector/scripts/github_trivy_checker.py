import os
import json
import re
import shutil
import tempfile
import subprocess
from pathlib import Path
from abc import ABC
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor
from shutil import which
import asyncio
import base64

from crawler.common.crawler_instance.local_interface_model.api.api_apk_model import apk_data_model
from crawler.common.crawler_instance.local_interface_model.api.api_collector_interface import api_collector_interface
from crawler.common.crawler_instance.local_shared_model.data_model.apk_model import apk_model
from crawler.common.crawler_instance.local_shared_model.data_model.entity_model import entity_model
from crawler.common.crawler_instance.local_shared_model import RuleModel, FetchProxy, FetchConfig, ThreatType


# ---------------- helpers ----------------

def _rm_rf(path: Path):
    if not path.exists():
        return

    def _onerror(func, p, excinfo):
        try:
            os.chmod(p, 0o777)
            func(p)
        except Exception:
            pass

    shutil.rmtree(path, onerror=_onerror, ignore_errors=True)


def _which(cmd: str) -> Optional[str]:
    p = which(cmd)
    if p:
        return p
    # Fallbacks for common locations
    fallbacks = [
        f"/usr/local/bin/{cmd}",
        f"/usr/bin/{cmd}",
        f"/bin/{cmd}",
    ]
    for fb in fallbacks:
        if os.path.exists(fb):
            return fb
    return None


def _run_blocking(
    cmd: List[str],
    cwd: Optional[Path] = None,
    timeout: int = 600,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            env=env,
        )
        return {
            "return_code": completed.returncode,
            "stdout": completed.stdout or "",
            "stderr": completed.stderr or "",
        }
    except subprocess.TimeoutExpired as te:
        return {"return_code": -1, "stdout": "", "stderr": f"timeout: {te}"}
    except FileNotFoundError as fe:
        return {"return_code": -1, "stdout": "", "stderr": str(fe)}
    except Exception as e:
        return {"return_code": -1, "stdout": "", "stderr": str(e)}


def _safe_int(x: Any, default: int) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _safe_bool(x: Any, default: bool = False) -> bool:
    if x is None:
        return default
    if isinstance(x, bool):
        return x
    if isinstance(x, (int, float)):
        return bool(x)
    if isinstance(x, str):
        return x.strip().lower() in ("1", "true", "yes", "y", "on")
    return default


def _name_for_file(repo_input: str) -> str:
    x = (repo_input or "").strip()
    x = x.replace("https://", "").replace("http://", "")
    x = x.replace(".git", "")
    x = re.sub(r"[^a-zA-Z0-9_\-\.]+", "_", x)
    return x[:180] or "repo"


def _home_cache_dir() -> Path:
    return Path.home() / ".cache" / "darkpulse" / "trivy_repos"


def _home_trivy_tmp() -> Path:
    return Path.home() / ".cache" / "darkpulse" / "trivy_tmp"


def _project_api_collector_root() -> Path:
    cwd = Path.cwd().resolve()
    if cwd.name == "api_collector":
        return cwd
    if (cwd / "api_collector").exists() and (cwd / "api_collector").is_dir():
        return (cwd / "api_collector").resolve()
    return cwd


def _make_git_auth_header(token: str) -> str:
    raw = f"x-access-token:{token}".encode("utf-8")
    b64 = base64.b64encode(raw).decode("ascii")
    return f"Authorization: Basic {b64}"


def _severity_key(sev: str) -> int:
    sev = (sev or "UNKNOWN").upper()
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    return order.get(sev, 9)


def grade_trivy_report(trivy_json: dict) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0, "SECRETS": 0}

    for r in (trivy_json.get("Results") or []):
        for v in (r.get("Vulnerabilities") or []):
            sev = (v.get("Severity") or "UNKNOWN").upper()
            counts[sev] = counts.get(sev, 0) + 1
        counts["SECRETS"] += len(r.get("Secrets") or [])

    score = (
        counts["CRITICAL"] * 10 +
        counts["HIGH"] * 5 +
        counts["MEDIUM"] * 2 +
        counts["LOW"] * 1 +
        counts["SECRETS"] * 8
    )

    if counts["CRITICAL"] > 0 or counts["SECRETS"] > 0:
        grade = "F"
    elif score >= 60:
        grade = "E"
    elif score >= 30:
        grade = "D"
    elif score >= 15:
        grade = "C"
    elif score >= 5:
        grade = "B"
    else:
        grade = "A"

    return {"counts": counts, "risk_score": score, "grade": grade}


def _detect_repo_inventory(repo_root: Path) -> dict:
    skip_dirs = {
        ".git", "node_modules", ".venv", "venv", "__pycache__", "dist",
        "build", "coverage", ".next", ".nuxt", "target", "vendor",
    }
    manifest_names = {
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "requirements.txt", "poetry.lock", "pipfile", "pipfile.lock",
        "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
        "go.mod", "go.sum", "cargo.toml", "cargo.lock", "composer.json",
        "composer.lock", "gemfile", "gemfile.lock", "mix.exs", "mix.lock",
        "pubspec.yaml", "pubspec.lock", "packages.config", "*.csproj",
    }
    config_names = {
        "dockerfile", "docker-compose.yml", "docker-compose.yaml",
        "compose.yml", "compose.yaml", "chart.yaml", ".trivyignore",
    }
    manifest_files: List[str] = []
    config_files: List[str] = []
    code_files = 0

    for root, dirs, files in os.walk(repo_root):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for file_name in files:
            rel_path = str((Path(root) / file_name).relative_to(repo_root))
            lower_name = file_name.lower()
            lower_rel = rel_path.lower()

            if lower_name in manifest_names or lower_rel.endswith((".csproj", ".tf", ".tfvars")):
                manifest_files.append(rel_path)
                continue

            if lower_name in config_names or lower_rel.endswith((".yaml", ".yml", ".json")) and "/.github/workflows/" in f"/{lower_rel}":
                config_files.append(rel_path)
                continue

            if lower_rel.endswith((
                ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php",
                ".rs", ".c", ".cc", ".cpp", ".cs", ".swift", ".kt", ".kts", ".scala",
                ".sh", ".html", ".css"
            )):
                code_files += 1

    return {
        "manifest_count": len(manifest_files),
        "config_count": len(config_files),
        "code_file_count": code_files,
        "supported_target_count": len(manifest_files) + len(config_files),
        "manifest_examples": manifest_files[:8],
        "config_examples": config_files[:8],
    }


def summarize_repo_posture(trivy_json: dict, repo_inventory: dict) -> dict:
    summary = grade_trivy_report(trivy_json)
    counts = summary["counts"]
    total_findings = (
        counts.get("CRITICAL", 0) +
        counts.get("HIGH", 0) +
        counts.get("MEDIUM", 0) +
        counts.get("LOW", 0) +
        counts.get("UNKNOWN", 0) +
        counts.get("SECRETS", 0)
    )

    if total_findings > 0:
        if summary["grade"] in {"F", "E", "D"}:
            posture_label = "High Risk"
            scan_status = "issues_found"
        else:
            posture_label = "Needs Review"
            scan_status = "issues_found"
        note = "DarkPulse found security issues in the scanned repository targets."
    elif repo_inventory.get("supported_target_count", 0) > 0:
        posture_label = "Healthy"
        scan_status = "clean"
        note = "No vulnerabilities, exposed secrets, or misconfigurations were detected in the supported repository targets."
    else:
        summary["grade"] = "B"
        posture_label = "Limited Coverage"
        scan_status = "limited"
        note = "The repository is valid, but Trivy found little or no supported dependency/config targets to analyze deeply."

    recommendations: List[str] = []
    if counts.get("SECRETS", 0) > 0:
        recommendations.append(
            "Remove hard-coded secrets from the repository, rotate any exposed tokens or private keys, and move them into environment-based secret storage."
        )
    if counts.get("CRITICAL", 0) or counts.get("HIGH", 0) or counts.get("MEDIUM", 0):
        recommendations.append(
            "Upgrade vulnerable dependencies, regenerate lockfiles, and rerun the scan until high, critical, and medium findings are cleared."
        )
    if repo_inventory.get("supported_target_count", 0) == 0:
        recommendations.append(
            "Add supported manifests or lockfiles such as package.json, package-lock.json, requirements.txt, Dockerfile, compose files, or IaC configs so DarkPulse can inspect the project deeply."
        )
    else:
        recommendations.append(
            "Keep manifests, lockfiles, and deployment configs committed so every dependency and build target can be evaluated consistently."
        )
    recommendations.append(
        "Enable CI security checks like Trivy, dependency updates, and secret scanning so risky changes are blocked before merge."
    )
    if summary["grade"] != "A":
        recommendations.append(
            "To reach grade A, keep secrets and vulnerable findings at zero while giving the scanner supported dependency or configuration targets to analyze."
        )
    else:
        recommendations.append(
            "Maintain grade A by scanning after dependency updates and reviewing pull requests for new secrets or vulnerable packages."
        )

    summary["posture_label"] = posture_label
    summary["scan_status"] = scan_status
    summary["note"] = note
    summary["coverage"] = repo_inventory
    summary["recommendations"] = recommendations[:5]
    return summary


def print_terminal_like(trivy_json: dict, max_items: int = 200) -> None:
    """
    Prints output like terminal:
      - Totals
      - Vulnerabilities list
      - Secrets list
    """
    summary = trivy_json.get("DarkpulseSummary") or grade_trivy_report(trivy_json)
    counts = summary["counts"]

    print("\n[TRIVY] ================= RESULTS =================")
    print(f"[TRIVY] Grade      : {summary['grade']}")
    print(f"[TRIVY] Risk Score : {summary['risk_score']}")
    print(f"[TRIVY] Totals     : MEDIUM={counts['MEDIUM']} HIGH={counts['HIGH']} CRITICAL={counts['CRITICAL']} SECRETS={counts['SECRETS']}")
    print("[TRIVY] ==========================================\n")

    results = trivy_json.get("Results") or []
    for r in results:
        target = r.get("Target") or "(unknown)"
        rtype = r.get("Type") or "(unknown)"
        vulns = r.get("Vulnerabilities") or []
        secrets = r.get("Secrets") or []
        print(f"[TRIVY] Target: {target} ({rtype}) | Vulns={len(vulns)} | Secrets={len(secrets)}")

    # Flatten
    all_v = []
    all_s = []
    for r in results:
        target = r.get("Target") or ""
        for v in (r.get("Vulnerabilities") or []):
            all_v.append((target, v))
        for s in (r.get("Secrets") or []):
            all_s.append((target, s))

    # Print vulns
    if all_v:
        print("\n[TRIVY] -------------- Vulnerabilities --------------")
        all_v.sort(key=lambda tv: (_severity_key(tv[1].get("Severity")), tv[1].get("PkgName") or "", tv[1].get("VulnerabilityID") or ""))
        for i, (target, v) in enumerate(all_v[:max_items], start=1):
            sev = (v.get("Severity") or "UNKNOWN").upper()
            vid = v.get("VulnerabilityID") or ""
            pkg = v.get("PkgName") or ""
            inst = v.get("InstalledVersion") or ""
            fix = v.get("FixedVersion") or ""
            title = (v.get("Title") or v.get("Description") or "").replace("\n", " ").strip()
            if len(title) > 180:
                title = title[:180] + "..."
            url = v.get("PrimaryURL") or ""
            print(f"[{i:03d}] {sev:8} {vid} | {pkg} {inst} -> {fix}")
            print(f"      Target: {target}")
            print(f"      Title : {title}")
            if url:
                print(f"      URL   : {url}")
        if len(all_v) > max_items:
            print(f"[TRIVY] ... {len(all_v) - max_items} more vulnerabilities not printed")
        print("[TRIVY] -------------------------------------------\n")
    else:
        print("\n[TRIVY] No vulnerabilities found.\n")

    # Print secrets
    if all_s:
        print("[TRIVY] ------------------ Secrets ------------------")
        for i, (target, s) in enumerate(all_s[:max_items], start=1):
            sev = (s.get("Severity") or "UNKNOWN").upper()
            title = s.get("Title") or ""
            rule = s.get("RuleID") or ""
            path = s.get("Path") or ""
            sl = s.get("StartLine")
            el = s.get("EndLine")
            match = (s.get("Match") or "").replace("\n", " ").strip()
            if len(match) > 140:
                match = match[:140] + "..."
            print(f"[{i:03d}] {sev:8} {rule} | {title}")
            print(f"      File  : {path} (target: {target})")
            print(f"      Lines : {sl}-{el}")
            print(f"      Match : {match}")
        if len(all_s) > max_items:
            print(f"[TRIVY] ... {len(all_s) - max_items} more secrets not printed")
        print("[TRIVY] -------------------------------------------\n")
    else:
        print("[TRIVY] No secrets found.\n")


# ---------------- main class ----------------

class github_trivy_checker(api_collector_interface, ABC):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(github_trivy_checker, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, developer_name: str = "Muhammad Abdullah", developer_note: str = ""):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        self._developer_name = developer_name
        self._developer_note = developer_note

        self._apk_data: List[apk_model] = []
        self._entity_data: List[entity_model] = []
        self._is_crawled: bool = False
        self._last_query: Dict = {}
        self.callback = None

        self._executor = ThreadPoolExecutor(max_workers=2)
        self._last_platform = "github"

        print("[TRIVY] github_trivy_checker initialized ✅")

    def init_callback(self, callback=None):
        self.callback = callback

    def set_proxy(self, proxy: dict):
        self._proxy = proxy or {}

    def set_limits(self, max_pages: Optional[int] = None, max_items: Optional[int] = None):
        if max_pages is not None and int(max_pages) >= 1:
            self._max_pages = int(max_pages)
        if max_items is not None and int(max_items) >= 1:
            self._max_items = int(max_items)

    def reset_cache(self):
        self._apk_data.clear()
        self._entity_data.clear()
        self._is_crawled = False
        self._last_query = {}

    def contact_page(self) -> str:
        return "https://github.com/contact"

    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def seed_url(self) -> str:
        return "repo://trivy-scan"

    @property
    def base_url(self) -> str:
        return "https://github.com/"

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_threat_type=ThreatType.API,
            m_fetch_proxy=FetchProxy.NONE,
            m_fetch_config=FetchConfig.REQUESTS,
            m_resoource_block=False,
        )

    @property
    def apk_data(self) -> List[apk_model]:
        return self._apk_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def _detect_git(self) -> Optional[str]:
        return _which("git")

    def _detect_trivy_non_snap(self) -> Optional[str]:
        """ Tries /usr/local/bin/trivy first, then /usr/bin/trivy. """
        p = _which("trivy")
        if p and "/snap/" in p:
            # Look for other candidates if the first one is a snap
            for c in ["/usr/local/bin/trivy", "/usr/bin/trivy"]:
                if os.path.exists(c) and "/snap/" not in c:
                    return c
            return None
        return p

    def _normalize_repo(self, repo_input: str) -> Optional[Dict[str, str]]:
        repo_input = (repo_input or "").strip()
        if not repo_input:
            return None

        # owner/repo shortcut
        if re.match(r"^[\w\-.]+\/[\w\-.]+$", repo_input):
            owner_repo = repo_input
            return {
                "platform": "github",
                "owner_repo": owner_repo,
                "repo_url": f"https://github.com/{owner_repo}.git",
                "web_url": f"https://github.com/{owner_repo}",
            }

        m = re.search(r"github\.com[:/]{1,2}([^/]+/[^/]+)(?:\.git|/|$)", repo_input)
        if m:
            owner_repo = m.group(1).rstrip("/")
            return {
                "platform": "github",
                "owner_repo": owner_repo,
                "repo_url": f"https://github.com/{owner_repo}.git",
                "web_url": f"https://github.com/{owner_repo}",
            }
    async def parse_leak_data(self, query: Dict[str, str], context=None, found_entitie_=None, _file_=None):
        self._last_query = dict(query or {})
        self._apk_data.clear()
        self._entity_data.clear()
        self._is_crawled = False

        # Hardcoded Token Fix as requested
        repo_input = (query or {}).get("github") or (query or {}).get("repo") or ""
        git_token = (query or {}).get("git_token") or (query or {}).get("token") or ""
        
        timeout = _safe_int((query or {}).get("timeout"), 900)
        keep_workdir = _safe_bool((query or {}).get("keep_workdir"), False)
        print_details = _safe_bool((query or {}).get("print_details"), True)
        max_print = _safe_int((query or {}).get("max_print"), 200)

        def _empty_model(raw: dict):
            m = apk_data_model()
            setattr(m, "base_url", self.base_url)
            setattr(m, "content_type", ["github_trivy"])
            setattr(m, "raw_data", raw)
            setattr(m, "cards_data", self._apk_data)
            return m

        if not repo_input:
            msg = "missing query['github'] or query['repo']"
            print(f"[TRIVY] ❌ {msg}")
            return _empty_model({"error": msg})

        normalized = self._normalize_repo(repo_input)
        if not normalized:
            return _empty_model({"error": "invalid repo input", "input": repo_input})

        owner_repo = normalized.get("owner_repo", "")
        repo_url = normalized.get("repo_url", "")
        web_url = normalized.get("web_url", repo_input.replace(".git", ""))

        print("\n[TRIVY] ===============================")
        print(f"[TRIVY] Repo input : {repo_input}")
        print(f"[TRIVY] Repo URL   : {repo_url}")
        print(f"[TRIVY] Web URL    : {web_url}")
        print("[TRIVY] ===============================\n")

        git_bin = self._detect_git()
        trivy_bin = self._detect_trivy_non_snap()

        if not git_bin:
            return _empty_model({"error": "git not found in PATH"})

        if not trivy_bin:
            return _empty_model({
                "error": "Non-snap trivy not found (snap trivy gives metadata-only JSON).",
                "fix": "Install trivy as /usr/local/bin/trivy or /usr/bin/trivy (official binary/deb), not /snap/bin/trivy.",
                "current_trivy": _which("trivy"),
            })

        # Work dir
        base_dir = _home_cache_dir()
        base_dir.mkdir(parents=True, exist_ok=True)
        workdir = Path(tempfile.mkdtemp(prefix="repo_trivy_", dir=str(base_dir)))
        print(f"[TRIVY] Work dir  : {workdir}")

        # Report output
        api_root = _project_api_collector_root()
        report_dir = api_root / "scripts" / "trivy_reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        out_file = report_dir / f"{_name_for_file(repo_input)}.json"

        try:
            # Clone (safe auth header)
            clone_cmd: List[str] = [git_bin]
            if git_token and "github.com" in repo_url and repo_url.startswith("https://"):
                clone_cmd += ["-c", f"http.extraheader={_make_git_auth_header(git_token)}"]

            clone_cmd += ["clone", "--depth", "1", "--recurse-submodules", repo_url, str(workdir)]
            print(f"[TRIVY] Running   : {git_bin} clone --depth 1 --recurse-submodules <repo> <dir>")
            clone_res = self._executor.submit(_run_blocking, clone_cmd, None, max(60, int(timeout / 6)), None).result()

            if clone_res["return_code"] != 0:
                err_msg = f"git clone failed: {clone_res.get('stderr', 'unknown error')}"
                print(f"[TRIVY] ❌ {err_msg}")
                return _empty_model({
                    "error": "git clone failed",
                    "stderr": clone_res["stderr"],
                    "stdout": clone_res["stdout"],
                    "command": " ".join(clone_cmd).replace(git_token, "********") if git_token else " ".join(clone_cmd)
                })

            # Trivy env
            env = os.environ.copy()
            tmpdir = _home_trivy_tmp()
            tmpdir.mkdir(parents=True, exist_ok=True)
            env["TMPDIR"] = str(tmpdir)

            # Trivy scan (same style as your terminal)
            trivy_cmd = [
                trivy_bin, "fs",
                "--severity", "CRITICAL,HIGH,MEDIUM",
                "--scanners", "vuln,secret",
                "--include-dev-deps",
                "--format", "json",
                "--output", str(out_file),
                str(workdir),
            ]
            print(f"[TRIVY] Running   : {' '.join(trivy_cmd)}")
            scan_res = self._executor.submit(_run_blocking, trivy_cmd, None, timeout, env).result()

            # 0 no findings, 2 findings
            if scan_res["return_code"] not in (0, 2) or not out_file.exists():
                print("[TRIVY] ❌ trivy failed")
                print("[TRIVY] stderr:", scan_res["stderr"][:4000])
                return _empty_model({
                    "error": "trivy failed",
                    "return_code": scan_res["return_code"],
                    "stderr": scan_res["stderr"],
                    "stdout": scan_res["stdout"],
                })

            trivy_json = json.loads(out_file.read_text(encoding="utf-8"))
            repo_inventory = _detect_repo_inventory(workdir)

            if trivy_json.get("Results") is None:
                trivy_json["Results"] = []

            summary = summarize_repo_posture(trivy_json, repo_inventory)
            trivy_json["DarkpulseSummary"] = summary
            trivy_json["DarkpulseMeta"] = {
                "repo_input": repo_input,
                "repo_url": repo_url,
                "web_url": web_url,
                "report_path": str(out_file),
                "trivy_path": trivy_bin,
                "trivy_return_code": scan_res["return_code"],
                "raw_keys": list(trivy_json.keys()),
                "coverage": repo_inventory,
            }

            print("\n[TRIVY] ✅ Scan complete")
            print(f"[TRIVY] Repo   : {web_url}")
            print(f"[TRIVY] Report : {out_file.resolve()}")
            print(f"[TRIVY] Code   : {scan_res['return_code']} (0=no findings, 2=findings)")

            if print_details:
                print_terminal_like(trivy_json, max_items=max_print)

            # UI card
            card = apk_model()
            setattr(card, "m_app_name", f"Trivy Scan: {owner_repo}")
            setattr(card, "m_app_url", web_url)
            setattr(card, "m_package_id", str(owner_repo).replace("/", "_"))
            setattr(card, "m_network", "clearnet")
            setattr(card, "m_content_type", ["github_trivy"])
            setattr(card, "m_latest_date", "")
            setattr(card, "m_description", f"Report saved: {out_file}")
            setattr(card, "m_extra", {
                "repo_input": repo_input,
                "repo_url": repo_url,
                "web_url": web_url,
                "report_path": str(out_file),
                "trivy_return_code": scan_res["return_code"],
                "grade": summary["grade"],
                "risk_score": summary["risk_score"],
                "counts": summary["counts"],
            })

            self._apk_data.append(card)
            self._entity_data.append(entity_model(m_scrap_file=self.__class__.__name__, m_team="api_collector"))
            self._is_crawled = True
            return _empty_model(trivy_json)

        finally:
            if keep_workdir:
                print(f"[TRIVY] (keep_workdir=true) Work dir kept: {workdir}")
            else:
                _rm_rf(workdir)

    def run(self) -> dict:
        q = self._last_query or {"github": "https://github.com/OWASP/NodeGoat"}
        try:
            result = asyncio.run(self.parse_leak_data(query=q, context=None))
            items = len(getattr(result, "cards_data", []) or []) if result else 0
        except Exception as e:
            print("[TRIVY] run() failed:", e)
            items = 0

        return {
            "seed_url": self.seed_url,
            "items_collected": items,
            "developer_signature": self.developer_signature(),
        }

    def developer_signature(self) -> str:
        return "Muhammad Abdullah"
