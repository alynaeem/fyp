from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from playwright.sync_api import Page

from crawler.common.crawler_instance.crawler_services.log_manager.log_controller import log
from crawler.common.crawler_instance.crawler_services.shared.helper_method import helper_method


class TweetHelperMethods:
    def __init__(self):
        self.seen_ids = set()

    @staticmethod
    def extract_username(url: str) -> str:
        m = re.search(
            r'^(?:https?://)?(?:www\.)?(?:twitter\.com|x\.com)/(?:@?)([A-Za-z0-9_]{1,15})',
            url
        )
        if m:
            return m.group(1)
        raise ValueError(f"Invalid Twitter URL: {url}")

    @staticmethod
    def extract_weblinks(text: str) -> List[str]:
        return re.findall(r'(https?://[^\s]+)', text or "")

    def get_tweets_from_page(self, profile_page: Page, username: str) -> List[Dict[str, Any]]:
        tweets = []
        articles = profile_page.query_selector_all("article")

        for art in articles:
            try:
                a = art.query_selector('a[href*="/status/"]')
                if not a:
                    continue

                href = a.get_attribute("href") or ""
                tid = href.split("/status/")[1].split("?")[0]

                if tid in self.seen_ids:
                    continue

                divs = art.query_selector_all('div[data-testid="tweetText"]')
                text = " ".join(d.inner_text() for d in divs if d)

                time_el = art.query_selector("time")
                ts = time_el.get_attribute("datetime") if time_el else ""

                tweets.append(
                    {
                        "id": tid,
                        "date": ts,
                        "content": text,
                        "url": f"https://x.com/{username}/status/{tid}",
                        "weblink": self.extract_weblinks(text),
                        "comment_count": 0,
                        "retweets": 0,
                        "likes": 0,
                        "views": 0,
                    }
                )
                self.seen_ids.add(tid)

            except Exception as ex:
                log.g().e(f"SCRIPT ERROR {ex} | TweetHelperMethods")

        return tweets

    def scroll_and_collect(
        self,
        profile_page: Page,
        username: str,
        existing_ids: Set[str],
        desired_count: int,
        max_scrolls: int = 50,
    ) -> List[Dict[str, Any]]:

        collected = []
        scrolls = 0

        while len(collected) < desired_count and scrolls < max_scrolls:
            profile_page.evaluate("window.scrollBy(0, 3000)")
            time.sleep(1.2)

            tweets = self.get_tweets_from_page(profile_page, username)
            for t in tweets:
                if t["id"] not in existing_ids:
                    collected.append(t)
                    existing_ids.add(t["id"])
                    if len(collected) >= desired_count:
                        break

            scrolls += 1

        return collected
