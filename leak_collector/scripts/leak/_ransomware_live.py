import re
from bs4 import BeautifulSoup
from abc import ABC
from datetime import datetime
from typing import List
from playwright.sync_api import Page
from urllib.parse import urljoin
from crawler.constants.constant import RAW_PATH_CONSTANTS
from crawler.crawler_instance.local_interface_model.leak.leak_extractor_interface import leak_extractor_interface
from crawler.crawler_instance.local_shared_model.data_model.entity_model import entity_model
from crawler.crawler_instance.local_shared_model.data_model.leak_model import leak_model
from crawler.crawler_instance.local_shared_model.rule_model import RuleModel, FetchProxy, FetchConfig, ThreatType
from crawler.crawler_services.log_manager.log_controller import log
from crawler.crawler_services.redis_manager.redis_controller import redis_controller
from crawler.crawler_services.redis_manager.redis_enums import REDIS_COMMANDS, CUSTOM_SCRIPT_REDIS_KEYS
from crawler.crawler_services.shared.helper_method import helper_method


class _ransomware_live(leak_extractor_interface, ABC):
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
            cls._instance = super(_ransomware_live, cls).__new__(cls)
        return cls._instance

    @property
    def is_crawled(self) -> bool:
        return self._is_crawled

    @property
    def developer_signature(self) -> str:
        return "Muhammad Abdullah:owGbwMvMwMEYdOzLoajv79gZTxskMWRU6bi8370 / LLUoMy0zNUUhJbUsNSe / ILXISsG3NCMxNzcxRcExKaU0Jycxg5erYzMLAyMHg6yYIkuQ4M9 / l7siYpT2b / oFM5GVCWQcAxenAEykRYSFYcHRJWUetXMKmo78Ec5ueHZq52rX / vuHpJTf / G31ULsywdC23 + fM4tmaUbP2cXYm7y9kPHnAdbXgspWerkeXW8ZYmm2xrpdTF / Yyvi0aGdn5iMne8PQGgSgWxeOMKUo8IQvL3W1PN4gtYYkxfr6kMZ3t0tmSRR2qnu / fZ2yfqfdm9szOQpt2AA ===weDX"

    @property
    def seed_url(self) -> str:
        return "https://www.ransomware.live/"

    @property
    def base_url(self) -> str:
        return "https://www.ransomware.live/"

    @property
    def card_data(self) -> List[leak_model]:
        return self._card_data

    @property
    def entity_data(self) -> List[entity_model]:
        return self._entity_data

    def invoke_db(self, command: int, key: str, default_value, expiry: int = None):
        return self._redis_instance.invoke_trigger(command, [key + self.__class__.__name__, default_value, expiry])

    def contact_page(self) -> str:
        return "https://ransomwarelive.freshdesk.com/support/tickets/new"

    @property
    def rule_config(self) -> RuleModel:
        return RuleModel(m_fetch_proxy=FetchProxy.NONE, m_fetch_config=FetchConfig.PLAYRIGHT, m_resoource_block=False, m_threat_type= ThreatType.LEAK)

    def append_leak_data(self, leak: leak_model, entity: entity_model):
        self._card_data.append(leak)
        self._entity_data.append(entity)
        if self.callback and self.callback():
            self._card_data.clear()
            self._entity_data.clear()

    def parse_leak_data(self, page: Page):
        # Use a less strict wait state to avoid timeouts on slow assets
        try:
            page.wait_for_load_state("domcontentloaded", timeout=20000)
        except Exception:
            pass

        # Scroll to load all 100 cards visible on homepage
        try:
             for _ in range(5):
                 page.evaluate("window.scrollBy(0, 1500)")
                 page.wait_for_timeout(1000)
             page.wait_for_selector("div.card", timeout=15000)
        except Exception:
            log.g().i("Finished scrolling / waiting for cards.")

        html = page.content()
        soup = BeautifulSoup(html, "html.parser")
        
        # Deep-Crawl Logic: Iterate through discovered links and visit detailed pages
        discovered_victims = []
        
        try:
            # Get links from Playwright first
            pw_cards = page.locator("a.victim-title").all()
            for link in pw_cards:
                href = link.get_attribute("href")
                if href:
                    discovered_victims.append(urljoin(self.base_url, href))
        except Exception:
            pass

        if not discovered_victims:
            # Fallback to BeautifulSoup for link discovery
            links = soup.find_all("a", class_="victim-title")
            for a in links:
                href = a.get("href")
                if href:
                    discovered_victims.append(urljoin(self.base_url, href))

        # Target 100 victims as requested by the user
        if len(discovered_victims) > 100:
            discovered_victims = discovered_victims[:100]
        
        # Ensure we have a reasonable amount if is_crawled is set
        if self.is_crawled and not discovered_victims:
             log.g().i("No victims discovered, check selectors.")
             return

        log.g().i(f"Visiting {len(discovered_victims)} detailed victim pages...")

        for victim_url in discovered_victims:
            try:
                page.goto(victim_url, timeout=30000, wait_until="domcontentloaded")
                # Wait for detail content
                try:
                    page.wait_for_selector("div.rl-contributor-box, h2", timeout=10000)
                except Exception:
                    pass

                detail_html = page.content()
                d_soup = BeautifulSoup(detail_html, "html.parser")

                # Extraction based on user-provided HTML
                title = d_soup.find("h2").get_text(strip=True) if d_soup.find("h2") else "Unknown"
                
                # Victim Website
                website = ""
                # Target the link that specifically contains the globe icon or has the secondary text class
                web_a = d_soup.find("a", class_="text-secondary", href=re.compile(r'^http'))
                if web_a:
                    website = web_a.get("href")

                # Group/Team
                group = "ransomware live"
                group_badge = d_soup.find("span", class_="rl-group-badge")
                if group_badge:
                    group = group_badge.get_text(strip=True)

                # Country
                country = ""
                country_a = d_soup.find("a", href=re.compile(r'^/map/'))
                if country_a and country_a.find("img"):
                    img = country_a.find("img")
                    country = img.get("alt") or img.get("title") or ""

                # Industry
                industry = ""
                industry_a = d_soup.find("a", href=re.compile(r'^/activity/'))
                if industry_a:
                    industry = industry_a.get_text(strip=True).replace("View more victims in", "").strip() or industry_a.get("title", "").replace("View more victims in", "").strip()

                # Description
                description = ""
                desc_box = d_soup.find("div", class_="rl-contributor-box")
                if desc_box:
                    description = desc_box.get_text(strip=True)

                # Dates
                discovered_at = datetime.today().date().isoformat()
                attack_date = ""
                date_ps = d_soup.find_all("p")
                for p in date_ps:
                    txt = p.get_text().lower()
                    if "discovered" in txt:
                        match = re.search(r'\d{4}-\d{2}-\d{2}', p.get_text())
                        if match: discovered_at = match.group(0)
                    if "attack date" in txt:
                        match = re.search(r'\d{4}-\d{2}-\d{2}', p.get_text())
                        if match: attack_date = match.group(0)

                # DNS Records
                dns = {"whois": [], "mx": [], "txt": []}
                dns_group = d_soup.find(id="dnsCardsGroup")
                if dns_group:
                    cols = dns_group.find_all("div", class_="col-md-4")
                    if len(cols) >= 1: # WHOIS
                        dns["whois"] = [li.get_text(strip=True) for li in cols[0].find_all("li", class_="list-group-item")]
                    if len(cols) >= 2: # MX
                        dns["mx"] = [li.get_text(strip=True) for li in cols[1].find_all("li", class_="list-group-item")]
                    if len(cols) >= 3: # TXT
                        dns["txt"] = [li.get_text(strip=True) for li in cols[2].find_all("li", class_="list-group-item")]

                # Cloud/SaaS
                saas = []
                saas_badges = d_soup.select(".rl-contributor-box span.badge")
                saas = [b.get_text(strip=True) for b in saas_badges]

                # Leak Screenshot URL
                leak_screenshot_url = ""
                screenshot_img = d_soup.find("img", alt="Leak Screenshot")
                if screenshot_img:
                    leak_screenshot_url = screenshot_img.get("src")

                # Build extra data
                extra = {
                    "website": website,
                    "industry": industry,
                    "attack_date": attack_date,
                    "discovered_at": discovered_at,
                    "dns_records": dns,
                    "saas_services": saas,
                    "original_screenshot_url": leak_screenshot_url
                }

                self._process_and_append(title, victim_url, group, country, description, extra, page)

            except Exception as ex:
                log.g().e(f"Error processing victim detail {victim_url}: {ex}")
                continue

    def _process_and_append(self, victim_name, victim_url, group, country, description, extra, page):
        # Determine leak date from extra if possible
        try:
            posted_on = datetime.strptime(extra.get("discovered_at"), "%Y-%m-%d").date()
        except Exception:
            posted_on = datetime.today().date()

        ref_html = ""
        # Screenshot is better taken on the detail page
        screenshot_base64 = ""
        try:
            screenshot_base64 = helper_method.get_screenshot_base64(page, victim_name, victim_url)
        except Exception:
            pass

        card_data = leak_model(
            m_ref_html=ref_html,
            m_title=victim_name,
            m_weblink=[victim_url],
            m_dumplink=[victim_url],
            m_url=victim_url,
            m_base_url=self.base_url,
            m_screenshot=screenshot_base64,
            m_content=description,
            m_network=helper_method.get_network_type(self.base_url),
            m_important_content=description,
            m_content_type=["leaks"],
            m_country=country,
            m_team=group,
            m_leak_date=posted_on,
            m_extra=extra
        )

        entity_data = entity_model(
            m_scrap_file=self.__class__.__name__,
            m_team=group,
        )
        self.append_leak_data(card_data, entity_data)
