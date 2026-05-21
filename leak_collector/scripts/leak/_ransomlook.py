import datetime
import re
from abc import ABC
from typing import List
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from playwright.sync_api import Page

from crawler.constants.constant import RAW_PATH_CONSTANTS
from crawler.crawler_instance.local_interface_model.leak.leak_extractor_interface import leak_extractor_interface
from crawler.crawler_instance.local_shared_model.data_model.entity_model import entity_model
from crawler.crawler_instance.local_shared_model.data_model.leak_model import leak_model
from crawler.crawler_instance.local_shared_model.rule_model import RuleModel, FetchProxy, FetchConfig, ThreatType
from crawler.crawler_services.log_manager.log_controller import log
from crawler.crawler_services.redis_manager.redis_controller import redis_controller
from crawler.crawler_services.redis_manager.redis_enums import CUSTOM_SCRIPT_REDIS_KEYS, REDIS_COMMANDS
from crawler.crawler_services.shared.helper_method import helper_method


class _ransomlook(leak_extractor_interface, ABC):
    _instance = None

    def __init__(self, callback=None):
        self.callback = callback
        self._card_data = []
        self._entity_data = []
        self._redis_instance = redis_controller()
        self._is_crawled = False

    def init_callback(self, callback=None):
        self.callback = callback

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(_ransomlook, cls).__new__(cls)
        return cls._instance

    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def developer_signature(self) -> str:
        return "Muhammad Abdullah: RansomLook Deep-Crawl"

    @property
    def seed_url(self) -> str:
        return "https://www.ransomlook.io/recent"

    @property
    def base_url(self) -> str:
        return "https://www.ransomlook.io"

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(m_fetch_proxy=FetchProxy.NONE, m_fetch_config=FetchConfig.PLAYRIGHT, m_threat_type=ThreatType.LEAK)

    @property
    def card_data(self) -> List[leak_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def invoke_db(self, command: int, key: str, default_value, expiry: int = None):
        return self._redis_instance.invoke_trigger(command, [key + self.__class__.__name__, default_value, expiry])

    def contact_page(self) -> str:
        return "https://www.ransomlook.io/about"

    def append_leak_data(self, leak: leak_model, entity: entity_model):
        self._card_data.append(leak)
        self._entity_data.append(entity)
        if self.callback and self.callback():
            self._card_data.clear()
            self._entity_data.clear()

    def parse_leak_data(self, page: Page):
        try:
            log.g().i(f"Navigating to RansomLook Recent: {self.seed_url}")
            page.goto(self.seed_url, timeout=60000, wait_until="domcontentloaded")
            page.wait_for_selector("table tbody tr", timeout=15000)

            html = page.content()
            soup = BeautifulSoup(html, "html.parser")
            rows = soup.select("table tbody tr")
            
            log.g().i(f"Found {len(rows)} potential leak entries on RansomLook.")

            discovered_entries = []
            for row in rows:
                cols = row.find_all("td")
                if len(cols) >= 3:
                    date_str = cols[0].get_text(strip=True)
                    victim_name = cols[1].get_text(strip=True)
                    group_a = cols[2].find("a")
                    
                    if group_a:
                        group_name = group_a.get_text(strip=True)
                        group_url = urljoin(self.base_url, group_a.get("href"))
                        discovered_entries.append({
                            "date": date_str,
                            "victim": victim_name,
                            "group": group_name,
                            "group_url": group_url
                        })

            # Limit for performance
            if self.is_crawled or len(discovered_entries) > 30:
                discovered_entries = discovered_entries[:30]

            log.g().i(f"Processing {len(discovered_entries)} RansomLook entries with Deep-Crawl...")

            # Group cache to avoid redundant detail page visits
            group_cache = {}

            for entry in discovered_entries:
                group_url = entry["group_url"]
                group_name = entry["group"]
                
                if group_url not in group_cache:
                    log.g().i(f"Crawling Group Details: {group_name}")
                    try:
                        page.goto(group_url, timeout=30000, wait_until="domcontentloaded")
                        detail_html = page.content()
                        d_soup = BeautifulSoup(detail_html, "html.parser")
                        
                        description = ""
                        desc_el = d_soup.select_one(".description, .content")
                        if desc_el:
                            description = desc_el.get_text(strip=True)
                            
                        badges = [b.get_text(strip=True) for b in d_soup.select(".status-badge, .badge")]
                        
                        analysis_links = []
                        analysis_section = d_soup.find(string=re.compile("External Analysis", re.I))
                        if analysis_section:
                            parent = analysis_section.find_parent("details") or analysis_section.find_parent("div")
                            if parent:
                                analysis_links = [a.get("href") for a in parent.find_all("a") if a.get("href")]

                        notes = []
                        notes_section = d_soup.find(string=re.compile("Ransom notes", re.I))
                        if notes_section:
                            parent = notes_section.find_parent("details") or notes_section.find_parent("div")
                            if parent:
                                notes = [li.get_text(strip=True) for li in parent.find_all("li")]

                        group_cache[group_url] = {
                            "description": description,
                            "badges": badges,
                            "analysis": analysis_links,
                            "notes": notes
                        }
                    except Exception as e:
                        log.g().e(f"Error crawling group {group_name}: {e}")
                        group_cache[group_url] = {"description": "", "badges": [], "analysis": [], "notes": []}

                # Build full metadata for this victim
                g_data = group_cache[group_url]
                try:
                    posted_on = datetime.datetime.strptime(entry["date"], "%Y-%m-%d").date()
                except Exception:
                    posted_on = datetime.date.today()

                extra = {
                    "group_description": g_data["description"],
                    "labels": g_data["badges"],
                    "external_analysis": g_data["analysis"],
                    "ransom_notes": g_data["notes"],
                    "source_platform": "RansomLook"
                }

                # Screenshot
                screenshot_base64 = ""
                try:
                    screenshot_base64 = helper_method.get_screenshot_base64(page, entry["victim"], self.base_url)
                except Exception:
                    pass

                card_data = leak_model(
                    m_title=entry["victim"],
                    m_url=group_url,
                    m_base_url=self.base_url,
                    m_screenshot=screenshot_base64,
                    m_content=g_data["description"],
                    m_network=helper_method.get_network_type(self.base_url),
                    m_important_content=g_data["description"],
                    m_content_type=["leaks"],
                    m_team=group_name,
                    m_leak_date=posted_on,
                    m_extra=extra
                )

                entity_data = entity_model(
                    m_scrap_file=self.__class__.__name__,
                    m_team=group_name,
                )
                self.append_leak_data(card_data, entity_data)

        except Exception as ex:
            log.g().e(f"SCRIPT ERROR {ex} in RansomLook")
            if not self.is_crawled:
                raise
