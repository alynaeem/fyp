from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from playwright.sync_api import Page

from crawler.common.crawler_instance.crawler_services.log_manager.log_controller import log
from crawler.common.crawler_instance.crawler_services.shared.helper_method import helper_method


class RedditHelperMethod:
    """
    Playwright DOM helper for Reddit (clearnet + onion mirror).
    Works on subreddit listing pages and post pages (comments).
    """

    @staticmethod
    def _clean(s: str) -> str:
        return re.sub(r"\s+", " ", (s or "").strip())

    @staticmethod
    def _abs_from_page(page: Page, href: str) -> str:
        href = (href or "").strip()
        if not href:
            return ""
        if href.startswith("http://") or href.startswith("https://"):
            return href
        try:
            u = urlparse(page.url)
            base = f"{u.scheme}://{u.netloc}"
        except Exception:
            base = "https://www.reddit.com"
        return urljoin(base, href)

    @staticmethod
    def extract_subreddit_name(url: str, default: str = "politics") -> str:
        """
        If url contains /r/<name> returns it, otherwise returns default.
        This prevents 'Invalid subreddit URL' when seed_url is homepage.
        """
        if not url:
            return default
        m = re.search(r"/r/([A-Za-z0-9_]+)", url)
        if m:
            return m.group(1)
        return default

    @staticmethod
    def ensure_subreddit_url(seed_url: str, subreddit_name: str) -> str:
        """
        If seed_url is homepage (no /r/), produce /r/<subreddit>/ URL.
        Preserves onion vs clearnet host.
        """
        seed_url = (seed_url or "").strip()
        if "/r/" in seed_url:
            return seed_url if seed_url.endswith("/") else (seed_url + "/")

        # Build base origin from seed_url
        try:
            u = urlparse(seed_url)
            if u.scheme and u.netloc:
                origin = f"{u.scheme}://{u.netloc}"
            else:
                origin = seed_url.rstrip("/")
        except Exception:
            origin = seed_url.rstrip("/")

        if not origin:
            origin = "https://www.reddit.com"

        return f"{origin}/r/{subreddit_name}/"

    @staticmethod
    def extract_weblinks(text: str) -> List[str]:
        return re.findall(r"(https?://[^\s)>\]]+)", text or "")

    @staticmethod
    def _parse_iso(s: str) -> Optional[datetime]:
        if not s:
            return None
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return None

    # ────────────────────────────────────────────────
    # Metadata
    # ────────────────────────────────────────────────

    @staticmethod
    def get_subreddit_metadata(page: Page, subreddit_name: str) -> Dict[str, Any]:
        meta: Dict[str, Any] = {
            "name": subreddit_name,
            "bio": "",
            "created_date": "",
            "visibility": "public",
            "members": 0,
        }

        try:
            title_el = (
                page.query_selector('div#title.i18n-subreddit-title')
                or page.query_selector('h1[data-testid="subreddit-name"]')
                or page.query_selector("h1")
            )
            desc_el = (
                page.query_selector('div#description.i18n-subreddit-description')
                or page.query_selector('[data-testid="subreddit-description"]')
                or page.query_selector('div[data-click-id="subreddit"] p')
            )

            title_txt = RedditHelperMethod._clean(title_el.inner_text()) if title_el else ""
            desc_txt = RedditHelperMethod._clean(desc_el.inner_text()) if desc_el else ""

            if title_txt and desc_txt:
                meta["bio"] = f"{title_txt}: {desc_txt}"
            elif desc_txt:
                meta["bio"] = desc_txt
            elif title_txt:
                meta["bio"] = title_txt

            created_time = page.query_selector("faceplate-timeago > time[datetime]") or page.query_selector("time[datetime]")
            if created_time:
                meta["created_date"] = (created_time.get_attribute("datetime") or "").strip()

            member_el = (
                page.query_selector("strong#subscribers")
                or page.query_selector('[data-testid="subreddit-subscribers"]')
            )
            if member_el:
                t = RedditHelperMethod._clean(member_el.inner_text()).lower()
                m = re.search(r"([\d.,]+)\s*([km]?)", t)
                if m:
                    num = float(m.group(1).replace(",", ""))
                    mult = m.group(2)
                    if mult == "k":
                        num *= 1_000
                    elif mult == "m":
                        num *= 1_000_000
                    meta["members"] = int(num)

        except Exception as ex:
            log.g().e(f"[RedditHelperMethod] metadata error: {ex}")

        return meta

    # ────────────────────────────────────────────────
    # Posts (listing page)
    # ────────────────────────────────────────────────

    @staticmethod
    def _extract_post_id_from_href(href: str) -> Optional[str]:
        href = href or ""
        m = re.search(r"/comments/([a-z0-9]+)/", href, flags=re.I)
        if m:
            return f"t3_{m.group(1)}"
        return None

    @staticmethod
    def get_posts_from_page(page: Page, subreddit_name: str) -> List[Dict[str, Any]]:
        posts: List[Dict[str, Any]] = []
        seen: set[str] = set()

        containers = []
        try:
            containers = page.query_selector_all('article[data-testid="post-container"]')
        except Exception:
            containers = []

        if not containers:
            try:
                containers = page.query_selector_all("shreddit-post")
            except Exception:
                containers = []

        if not containers:
            try:
                containers = page.query_selector_all("article")
            except Exception:
                containers = []

        for c in containers:
            try:
                title = ""
                href = ""

                title_el = (
                    c.query_selector('a[id^="post-title-"]')
                    or c.query_selector('a[data-testid="post-title"]')
                    or c.query_selector('a[href*="/comments/"]')
                )
                if title_el:
                    title = RedditHelperMethod._clean(title_el.inner_text())
                    href = (title_el.get_attribute("href") or "").strip()

                post_url = RedditHelperMethod._abs_from_page(page, href)

                post_id = None
                if title_el:
                    tid = (title_el.get_attribute("id") or "").strip()
                    m = re.search(r"post-title-(t3_[A-Za-z0-9]+)", tid)
                    if m:
                        post_id = m.group(1)

                if not post_id:
                    post_id = RedditHelperMethod._extract_post_id_from_href(href)

                if not post_id:
                    a2 = c.query_selector('a[href*="/comments/"]')
                    h2 = (a2.get_attribute("href") or "").strip() if a2 else ""
                    post_id = RedditHelperMethod._extract_post_id_from_href(h2)

                if not post_id or post_id in seen:
                    continue
                seen.add(post_id)

                username = ""
                u_el = c.query_selector('a[href^="/user/"]') or c.query_selector('a[href*="/user/"]')
                if u_el:
                    username = RedditHelperMethod._clean(u_el.inner_text()).replace("u/", "").strip()
                if not username:
                    username = "unknown"

                timestamp = ""
                t_el = c.query_selector("faceplate-timeago time[datetime]") or c.query_selector("time[datetime]")
                if t_el:
                    timestamp = (t_el.get_attribute("datetime") or "").strip()

                weblinks: List[str] = []
                try:
                    for a in c.query_selector_all('a[href^="http"]'):
                        h = (a.get_attribute("href") or "").strip()
                        if not h:
                            continue
                        if h.startswith("http") and h not in weblinks:
                            if "reddit.com" not in h and "redd.it" not in h:
                                weblinks.append(h)
                except Exception:
                    pass

                posts.append(
                    {
                        "id": post_id,
                        "url": post_url,
                        "title": title,
                        "username": username,
                        "content": "",
                        "timestamp": timestamp,
                        "weblinks": weblinks,
                    }
                )

            except Exception:
                continue

        return posts

    # ────────────────────────────────────────────────
    # Comments (post page)
    # ────────────────────────────────────────────────

    @staticmethod
    def get_comments_from_post(page: Page, post_url: str, max_comments: int = 5) -> List[Dict[str, Any]]:
        comments: List[Dict[str, Any]] = []
        if not post_url:
            return comments

        try:
            page.goto(post_url, wait_until="domcontentloaded", timeout=60_000)
            page.wait_for_timeout(1200)
        except Exception as ex:
            log.g().e(f"[RedditHelperMethod] goto post error: {ex}")
            return comments

        # Post body (best-effort)
        post_body = ""
        try:
            loc = page.locator('div[property="schema:articleBody"]').first
            if loc.count() > 0:
                post_body = RedditHelperMethod._clean(loc.inner_text(timeout=0))
        except Exception:
            post_body = ""

        # Comment elements (new + old)
        try:
            els = page.query_selector_all("shreddit-comment")
        except Exception:
            els = []
        if not els:
            try:
                els = page.query_selector_all('[data-testid="comment"]')
            except Exception:
                els = []

        for el in els[: max_comments or 0]:
            try:
                ts = ""
                txt = ""

                t_el = el.query_selector('time[datetime]') or el.query_selector('faceplate-timeago time[datetime]')
                if t_el:
                    ts = (t_el.get_attribute("datetime") or "").strip()

                c_el = (
                    el.query_selector('div[id*="comment"] p')
                    or el.query_selector('[data-testid="comment-content"]')
                    or el.query_selector("p")
                )
                if c_el:
                    txt = RedditHelperMethod._clean(c_el.inner_text())

                if txt:
                    try:
                        txt = helper_method.filter_comments(txt)
                    except Exception:
                        pass

                if txt:
                    comments.append({"timestamp": ts, "content": txt})

            except Exception:
                continue

        # If no comments captured but body exists, return body as one item
        if not comments and post_body:
            comments.append({"timestamp": "", "content": post_body})

        return comments

    # ────────────────────────────────────────────────
    # Scroll collector
    # ────────────────────────────────────────────────

    @staticmethod
    def scroll_and_collect_posts(
        page: Page,
        subreddit_name: str,
        desired_count: int,
        max_scrolls: int = 1000,
        filter_date: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:

        collected: List[Dict[str, Any]] = []
        seen_ids: set[str] = set()

        # Let initial DOM settle
        try:
            page.wait_for_timeout(1500)
        except Exception:
            pass

        stagnation = 0

        for _ in range(max_scrolls):
            posts = RedditHelperMethod.get_posts_from_page(page, subreddit_name)

            if not posts:
                stagnation += 1
            else:
                new_found = False
                for post in posts:
                    pid = post.get("id")
                    if not pid or pid in seen_ids:
                        continue

                    # filter by time
                    if filter_date and post.get("timestamp"):
                        dt = RedditHelperMethod._parse_iso(post["timestamp"])
                        if dt and dt < filter_date:
                            return collected

                    seen_ids.add(pid)
                    collected.append(post)
                    new_found = True
                    if len(collected) >= desired_count:
                        return collected

                if not new_found:
                    stagnation += 1
                else:
                    stagnation = 0

            # click load more if exists
            clicked = False
            for sel in [
                "button:has-text('Load more')",
                "button:has-text('More')",
                'button[aria-label*="Load"]',
            ]:
                try:
                    b = page.query_selector(sel)
                    if b and b.is_enabled():
                        b.click()
                        clicked = True
                        page.wait_for_timeout(1600)
                        break
                except Exception:
                    continue

            if not clicked:
                try:
                    page.evaluate("window.scrollBy(0, Math.max(12000, document.body.scrollHeight * 0.75));")
                except Exception as ex:
                    log.g().e(f"[RedditHelperMethod] scroll error: {ex}")

                try:
                    page.wait_for_timeout(1800)
                except Exception:
                    pass

            if stagnation >= 15:
                break

            time.sleep(0.01)

        return collected
