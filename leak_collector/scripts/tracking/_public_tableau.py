import re
import json
import hashlib
from abc import ABC
from datetime import datetime, timezone, date
from time import sleep
from typing import List, Optional, Callable, Dict

from bs4 import BeautifulSoup
from playwright.sync_api import Page, sync_playwright, TimeoutError as PlaywrightTimeoutError

from crawler.common.crawler_instance.local_interface_model.leak.leak_extractor_interface import leak_extractor_interface
from crawler.common.crawler_instance.local_shared_model.data_model.entity_model import entity_model
from crawler.common.crawler_instance.local_shared_model.data_model.leak_model import leak_model
from crawler.common.crawler_instance.local_shared_model.rule_model import RuleModel, FetchProxy, FetchConfig, ThreatType
from crawler.common.crawler_instance.crawler_services.log_manager.log_controller import log
from crawler.common.crawler_instance.crawler_services.redis_manager.redis_controller import redis_controller
from crawler.common.crawler_instance.crawler_services.shared.helper_method import helper_method


class _public_tableau(leak_extractor_interface, ABC):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(_public_tableau, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, developer_name: str = "Anonymous", developer_note: str = "", callback: Optional[Callable[[], None]] = None):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True

        self.callback = callback
        self._card_data: List[leak_model] = []
        self._entity_data: List[entity_model] = []
        self._redis = redis_controller()
        self._is_crawled = False
        self._developer_name = developer_name
        self._developer_note = developer_note

        self._max_pages_first_crawl: int = 12
        self._max_pages_next_crawl: int = 6
        self._max_retries: int = 15

        self._raw_index_key = "PUBLIC:TABLEAU:raw_index"
        self._json_index_key = "PUBLIC:TABLEAU:json_index"
        self._seen_index_key = "PUBLIC:TABLEAU:seen_index"

        self._fixed_signature = "name:signature"

        self.page: Optional[Page] = None
        self._page: Optional[Page] = None
        self._context_page: Optional[Page] = None

    def init_callback(self, callback=None):
        self.callback = callback

    @property
    def seed_url(self) -> str:
        return (
            "https://public.tableau.com/views/DataBreachChronologyFeatures/ChronologyofDataBreaches"
            "?%3Aembed=y&%3AshowVizHome=no&%3Ahost_url=https%3A%2F%2Fpublic.tableau.com%2F"
            "&%3Aembed_code_version=3&%3Atabs=no&%3Atoolbar=yes&%3Aanimate_transition=yes"
            "&%3Adisplay_static_image=no&%3Adisplay_spinner=no&%3Adisplay_overlay=yes"
            "&%3Adisplay_count=yes&%3Alanguage=en-US"
        )

    @property
    def base_url(self) -> str:
        return "https://public.tableau.com"

    @property
    def developer_signature(self) -> str:
        return self._fixed_signature

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(
            m_timeout=180000,
            m_resoource_block=False,
            m_fetch_proxy=FetchProxy.NONE,
            m_fetch_config=FetchConfig.PLAYWRIGHT,
            m_threat_type=ThreatType.TRACKING,
        )

    @property
    def card_data(self) -> List[leak_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    def contact_page(self) -> str:
        return "https://privacyrights.org/contact"

    def _redis_get(self, key: str, default: str = "") -> str:
        try:
            val = self._redis.invoke_trigger(1, [key, default, None])
            return str(val) if val is not None else default
        except Exception:
            return default

    def _redis_set(self, key: str, value: object, expiry: Optional[int] = None):
        val = "" if value is None else str(value)
        try:
            self._redis.invoke_trigger(2, [key, val, expiry])
        except Exception:
            pass

    def _append_index(self, index_key: str, item_id: str):
        cur = self._redis_get(index_key, "")
        parts = [p for p in cur.split("|") if p]
        if item_id not in parts:
            parts.append(item_id)
            self._redis_set(index_key, "|".join(parts))

    def _has_seen(self, item_id: str) -> bool:
        cur = self._redis_get(self._seen_index_key, "")
        return item_id in [p for p in cur.split("|") if p]

    def _mark_seen(self, item_id: str):
        self._append_index(self._seen_index_key, item_id)

    @staticmethod
    def _sha1(text: str) -> str:
        return hashlib.sha1(text.encode("utf-8")).hexdigest()

    @staticmethod
    def _clean_text(s: str) -> str:
        return re.sub(r"\s+", " ", (s or "")).strip()

    def _get_page_from_framework(self) -> Optional[Page]:
        for attr in ("page", "_page", "_context_page"):
            try:
                p = getattr(self, attr, None)
                if p is not None:
                    return p
            except:
                continue
        return None

    def _run_with_own_playwright(self) -> dict:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
                viewport={"width": 1400, "height": 900}
            )
            page = context.new_page()

            def block_resources(route):
                if route.request.resource_type in ("image", "media", "font"):
                    route.abort()
                else:
                    route.continue_()

            context.route("**/*", block_resources)

            try:
                page.goto(self.seed_url, wait_until="domcontentloaded", timeout=120000)
                page.wait_for_timeout(15000)
                return self.parse_leak_data(page)
            except Exception as ex:
                log.g().e(f"Self Playwright failed: {ex}")
                return {"error": str(ex), "items_collected": 0}
            finally:
                page.close()
                context.close()
                browser.close()

    def append_leak_data(self, leak: leak_model, entity: entity_model):
        self._card_data.append(leak)
        self._entity_data.append(entity)
        if self.callback:
            try:
                if self.callback():
                    self._card_data.clear()
                    self._entity_data.clear()
            except:
                pass

    def run(self) -> dict:
        page = self._get_page_from_framework()
        if page is None:
            log.g().e("[PUBLIC.TABLEAU] No injected page → using self-launched Playwright")
            return self._run_with_own_playwright()
        return self.parse_leak_data(page)

    def parse_leak_data(self, page: Page) -> dict:
        collected = 0
        max_attempts = 30          # badha diya for more collection
        y_step = 16
        scroll_every = 10
        retry_count = 0

        try:
            page.wait_for_selector("div[id^='tabZone']", timeout=120000)
            page.wait_for_timeout(18000)
        except PlaywrightTimeoutError:
            log.g().e("Main viz zone not found")
            return {"items_collected": 0, "error": "viz_load_timeout"}

        viewport = page.viewport_size or {"width": 1400, "height": 900}
        x_pos = int(viewport["width"] * 0.78)

        y_pos = 100
        successful_hovers = 0

        for attempt in range(max_attempts):
            try:
                page.mouse.move(x_pos, y_pos, steps=10)
                page.wait_for_timeout(1200 + (attempt % 5) * 300)

                tooltip = None
                for _ in range(8):
                    tooltip = page.query_selector(".tab-tooltipContainer")
                    if tooltip and tooltip.is_visible() and len(tooltip.inner_text().strip()) > 40:
                        break
                    page.wait_for_timeout(1200)

                if not tooltip:
                    y_pos += y_step
                    retry_count += 1
                    if retry_count > 20:
                        page.mouse.wheel(0, 420)
                        y_pos = 100 + (attempt // 15) * 30
                        retry_count = 0
                    continue

                html = tooltip.inner_html()
                soup = BeautifulSoup(html, "html.parser")

                spans = soup.select(".tab-selection-relaxation")
                company_name = spans[0].get_text(strip=True) if spans else "Unknown"

                data_dict: Dict[str, str] = {}
                for table in soup.select("table"):
                    for row in table.find_all("tr"):
                        tds = row.find_all("td")
                        if len(tds) >= 3:
                            key = tds[0].get_text(strip=True).rstrip(":")
                            val = tds[2].get_text(strip=True)
                            data_dict[key] = val

                weblinks = re.findall(r"https?://[^\s<\"']+", html)

                m_important = data_dict.get("Incident Details", "")
                content_parts = [
                    data_dict.get("Incident Details", ""),
                    data_dict.get("Breach Type", ""),
                    data_dict.get("Organization Type", ""),
                    data_dict.get("Information Impacted", ""),
                ]
                content_parts = [self._clean_text(p) for p in content_parts if self._clean_text(p)]
                m_content = "\n".join(content_parts)

                leak_date = None
                leak_date_str = None
                for v in data_dict.values():
                    m = re.search(r"(\d{4}-\d{2}-\d{2})", v, re.I)
                    if m:
                        try:
                            leak_date_str = m.group(1)
                            leak_date = datetime.strptime(leak_date_str, "%Y-%m-%d").date()  # date object banao
                            break
                        except:
                            pass

                data_size = None
                affected = data_dict.get("Total Affected", "").strip()
                if affected and affected.upper() != "UNKN" and affected != "Unknown":
                    data_size = f"{affected} individuals"

                record_url = f"{self.base_url}/views/DataBreachChronologyFeatures/ChronologyofDataBreaches?company={company_name.replace(' ', '+')}"

                # Stronger dedupe
                dedupe_basis = f"{company_name.strip().lower()}|{leak_date_str or ''}|{m_important.strip()[:300]}|{data_dict.get('Breach Type', '').strip()}"
                aid = self._sha1(dedupe_basis)

                if self._has_seen(aid):
                    y_pos += y_step
                    continue

                card = leak_model(
                    m_title=company_name,
                    m_section=content_parts,
                    m_url=record_url,
                    m_base_url=self.base_url,
                    m_content=f"{m_content} {self.base_url} {page.url}".strip(),
                    m_network=helper_method.get_network_type(self.base_url),
                    m_important_content=m_important,
                    m_weblink=weblinks,
                    m_dumplink=[],
                    m_content_type=["news", "tracking"],
                    m_leak_date=leak_date,  # ab date object ya None
                    m_data_size=data_size,
                )

                ent = entity_model(
                    m_scrap_file=self.__class__.__name__,
                    m_country=["United States"],
                    m_company_name=company_name,
                    m_states=[data_dict.get("Breach Location State", "")] if "Breach Location State" in data_dict else [],
                    m_location=[data_dict.get("Breach Location State", "")] if "Breach Location State" in data_dict else [],
                    m_team="public tableau",
                    m_name="public tableau",
                )

                self.append_leak_data(card, ent)
                self._mark_seen(aid)
                self._append_index(self._raw_index_key, aid)
                self._append_index(self._json_index_key, aid)

                collected += 1
                successful_hovers += 1
                retry_count = 0

                log.g().i(f"Collected {collected}: {company_name}")

                if successful_hovers % scroll_every == 0:
                    page.mouse.wheel(0, 380)
                    y_pos = 100 + (successful_hovers // scroll_every) * 50

                y_pos += y_step + (attempt % 4) * 3

            except Exception as ex:
                log.g().e(f"Hover attempt {attempt} error: {ex}")
                retry_count += 1
                y_pos += y_step * 2

            if collected >= 30:  # badha diya, agar chaho to comment out kar dena
                break

        self._is_crawled = True
        return {
            "seed_url": self.seed_url,
            "items_collected": collected,
            "max_attempts": max_attempts,
            "developer_signature": self.developer_signature,
        }