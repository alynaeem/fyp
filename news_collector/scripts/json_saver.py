"""
Shared JSON output saver for all DarkPulse collectors.

Usage in any collector script:
    from news_collector.scripts.json_saver import save_collector_json

    # After crawling is done:
    save_collector_json(
        source="thehackernews",
        seed_url=self.seed_url,
        cards=self._card_data,
        output_dir=os.path.join(os.path.dirname(__file__), "output"),
        developer_signature=self.developer_signature(),
    )
"""
import json
import os
from datetime import datetime, timezone
from typing import Any, List, Optional


def _card_to_dict(card: Any) -> dict:
    """Convert a news_model / leak_model / entity_model to a plain dict."""
    # Most models store their fields with m_ prefix
    d: dict = {}
    for attr in dir(card):
        if attr.startswith("m_") and not callable(getattr(card, attr)):
            val = getattr(card, attr)
            # Convert date / datetime objects to ISO strings
            if hasattr(val, "isoformat"):
                val = val.isoformat()
            # Convert sets to lists
            if isinstance(val, set):
                val = list(val)
            d[attr[2:]] = val  # strip leading m_
    # Fallback: try __dict__
    if not d:
        try:
            d = {k: str(v) for k, v in card.__dict__.items()}
        except Exception:
            d = {"raw": str(card)}
    return d


def save_collector_json(
    source: str,
    seed_url: str,
    cards: List[Any],
    output_dir: str,
    developer_signature: Optional[str] = None,
    extra_meta: Optional[dict] = None,
) -> str:
    """
    Serialise collected card_data to a timestamped JSON file.

    Returns the path of the written file.
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"{source}_output_{timestamp}.json"
    output_path = os.path.join(output_dir, filename)

    articles = [_card_to_dict(c) for c in cards]

    payload = {
        "meta": {
            "source": source,
            "seed_url": seed_url,
            "articles_collected": len(articles),
            "scraped_at_utc": datetime.now(timezone.utc).isoformat(),
        },
        "data": articles,
    }

    if developer_signature:
        payload["meta"]["developer_signature"] = developer_signature
    if extra_meta:
        payload["meta"].update(extra_meta)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, default=str)

    print(f"[JSON] ✅ Saved {len(articles)} records → {output_path}")
    return output_path
