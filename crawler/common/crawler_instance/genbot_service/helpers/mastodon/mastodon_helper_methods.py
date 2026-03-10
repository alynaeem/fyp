import re
from typing import Dict, List, Set, Any

from playwright.sync_api import Page


class MastodonHelperMethods:
    def __init__(self):
        self.seen_ids: Set[str] = set()

    @staticmethod
    def get_profile_info(page: Page) -> Dict[str, Any]:
        info: Dict[str, Any] = {}
        try:
            username_elem = page.query_selector(".account__header__tabs__name h1 small span")
            username = username_elem.inner_text().strip() if username_elem else ""
            info = {"username": username}
        except Exception:
            pass
        return info

    @staticmethod
    def extract_weblinks(text: str) -> List[str]:
        url_pattern = r"(https?://[^\s]+)"
        return re.findall(url_pattern, text or "")

    def get_posts_from_page(self, page: Page, username: str) -> List[str]:
        posts: List[str] = []
        articles = page.query_selector_all('article[data-id]')
        for article in articles:
            try:
                post_id = article.get_attribute("data-id")
                if post_id and post_id not in self.seen_ids:
                    posts.append(post_id)
                    self.seen_ids.add(post_id)
            except Exception:
                continue
        return posts

    @staticmethod
    def extract_post_details(page: Page, post_id: str, seed_url: str) -> Dict[str, Any]:
        article = page.query_selector(f'article[data-id="{post_id}"]')
        if not article:
            return {}

        # date
        date_str = ""
        try:
            date_elem = page.wait_for_selector(
                f'article[data-id="{post_id}"] a.status__relative-time time',
                timeout=30000,
            )
            date_str = date_elem.get_attribute("datetime") if date_elem else ""
        except Exception:
            date_str = ""

        # boosted_by
        data_boosted_by = ""
        try:
            wrapper = article.query_selector("div.status__wrapper")
            data_boosted_by = wrapper.get_attribute("data-boosted_by") if wrapper else ""
        except Exception:
            data_boosted_by = ""

        # username
        username = ""
        try:
            username_elem = article.query_selector(".display-name__account")
            username = username_elem.inner_text().strip() if username_elem else ""
        except Exception:
            username = ""

        # content
        content = ""
        try:
            content_elem = article.query_selector("div.status__content__text")
            content = content_elem.inner_text().strip() if content_elem else ""
        except Exception:
            content = ""

        # url
        url = ""
        try:
            url_elem = article.query_selector("a.status__relative-time")
            url = url_elem.get_attribute("href") if url_elem else ""
        except Exception:
            url = ""

        # media
        media: List[str] = []
        try:
            media_elems = article.query_selector_all(".media-gallery__item-thumbnail img")
            for m in media_elems:
                src = m.get_attribute("src")
                if src:
                    media.append(src)
        except Exception:
            media = []

        # card title
        card_title = ""
        try:
            card_title_elem = article.query_selector(".status-card__title")
            card_title = card_title_elem.inner_text().strip() if card_title_elem else ""
        except Exception:
            card_title = ""

        result: Dict[str, Any] = {
            "id": post_id,
            "boosted_by": data_boosted_by,
            "username": username,
            "content": content,
            "date": date_str,
            "url": url,
            "media": media,
            "card_title": card_title,
            "weblinks": MastodonHelperMethods.extract_weblinks(content),
            "seed_url": seed_url,
        }

        # Optional fields if later you add them
        # result["boosts"] = None
        # result["favourites"] = None
        # result["comments"] = None

        return result

    def scroll_and_collect(
        self,
        page: Page,
        username: str,
        existing_ids: Set[str],
        desired_count: int,
        max_scrolls: int = 1050,
    ) -> List[str]:
        collected: List[str] = []
        local_seen_ids: Set[str] = set()
        scrolls = 0

        while len(collected) < desired_count and scrolls < max_scrolls:
            try:
                page.wait_for_selector('article[data-id]', timeout=30000)
            except Exception:
                break

            posts = self.get_posts_from_page(page, username)
            new_found = False

            for post in posts:
                if post not in existing_ids and post not in local_seen_ids:
                    collected.append(post)
                    local_seen_ids.add(post)
                    new_found = True
                    if len(collected) >= desired_count:
                        break

            if not new_found and scrolls > 5:
                break

            scrolls += 1
            try:
                page.evaluate(
                    """() => {
                        const items = document.querySelectorAll('article[data-id]');
                        if (items.length) items[items.length - 1].scrollIntoView();
                    }"""
                )
            except Exception:
                break

        return collected[:desired_count]
