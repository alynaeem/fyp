import time
import traceback
from typing import Any, Dict, List, Optional

import requests

# =========================
# ✅ ADD: optional Playwright support (safe import)
# =========================
try:
    from playwright.sync_api import sync_playwright, Page  # type: ignore
except Exception:
    sync_playwright = None  # type: ignore
    Page = None  # type: ignore


class RequestParser:
    def __init__(
        self,
        proxy: Dict[str, str] | None = None,
        model: Any = None,
        reset_cache: bool = False,
        strict: bool = False,
        seed_fetch: bool = False,              # ✅ NEW (default OFF)
        seed_timeout: int = 60,                # ✅ NEW
        # =========================
        # ✅ ADD: Playwright knobs (default OFF / safe)
        # =========================
        playwright_timeout: int = 30000,
        playwright_headless: bool = True,
    ):
        """
        proxy: {"server": "socks5://127.0.0.1:9150"}
        model: collector instance
        reset_cache: force model cache reset
        strict: if True -> raise errors, else log and continue
        seed_fetch: if True -> REQUESTS seed_url will be fetched & attached to model (safe opt-in)

        ✅ Added (non-breaking):
        - If model.rule_config.m_fetch_config == PLAYWRIGHT, we will create a Playwright Page,
          attach it to model (attach_page / page / _page / _request_page), and call model.run(page)
          with fallback to model.run().
        """
        self.proxy = proxy
        self.model = model
        self.reset_cache = reset_cache
        self.strict = strict
        self.seed_fetch = seed_fetch
        self.seed_timeout = seed_timeout

        # ✅ ADD
        self.playwright_timeout = playwright_timeout
        self.playwright_headless = playwright_headless

    def _validate_output(self, result: Any) -> List[Dict]:
        """
        Enforce: result must be List[Dict]
        """
        if result is None:
            return []

        if isinstance(result, dict):
            return [result]

        if isinstance(result, list):
            valid = []
            for item in result:
                if isinstance(item, dict):
                    valid.append(item)
            return valid

        return []

    def _build_requests_proxies(self) -> Optional[Dict[str, str]]:
        server = (self.proxy or {}).get("server")
        if not server:
            return None

        # Tor best-practice: socks5h (DNS through proxy)
        if server.startswith("socks5://"):
            server = server.replace("socks5://", "socks5h://", 1)

        return {"http": server, "https": server}

    def _requests_fetch_seed(self) -> Optional[requests.Response]:
        """
        Fetch model.seed_url using requests and attach response/html to model.
        Only called when enabled (opt-in).
        """
        if not self.model or not hasattr(self.model, "seed_url"):
            return None

        url = getattr(self.model, "seed_url", None)
        if not url:
            return None

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        }

        proxies = self._build_requests_proxies()

        print("\n[RequestParser][SEED_FETCH] Fetching seed_url (opt-in):")
        print(f"  URL: {url}")
        print(f"  Proxies: {proxies}")
        print(f"  Timeout: {self.seed_timeout}")

        s = requests.Session()
        s.headers.update(headers)

        resp = s.get(url, timeout=self.seed_timeout, proxies=proxies, allow_redirects=True)

        print(f"[RequestParser][SEED_FETCH] Status: {resp.status_code}")
        print(f"[RequestParser][SEED_FETCH] Final URL: {resp.url}")
        print(f"[RequestParser][SEED_FETCH] HTML length: {len(resp.text or '')}")

        # ✅ attach in a safe way (doesn't affect other scripts unless they use it)
        self.model._seed_response = resp
        self.model._seed_html = resp.text or ""

        # Some scripts may look for _request_page-like object
        class RequestsPage:
            def __init__(self, r: requests.Response):
                self._seed_response = r
                self.response = r
                self.text = r.text
                self.content = r.content
                self.url = r.url
                self.status_code = r.status_code

        self.model._request_page = RequestsPage(resp)
        return resp

    # =========================
    # ✅ ADD: helpers for Playwright detection + attach (non-breaking)
    # =========================
    def _wants_playwright(self) -> bool:
        if not self.model:
            return False

        # 1) if model explicitly says it needs a browser/page
        for flag in ("needs_playwright", "use_playwright", "needs_browser"):
            try:
                if bool(getattr(self.model, flag, False)):
                    return True
            except Exception:
                pass

        # 2) rule_config based detection
        try:
            rule = getattr(self.model, "rule_config", None)
            if rule is None:
                return False

            cfg = getattr(rule, "m_fetch_config", None)
            if cfg is None:
                return False

            s = str(cfg).upper()
            # covers: FetchConfig.PLAYRIGHT, PLAYWRIGHT, PW, BROWSER, etc
            if "PLAY" in s or "PW" == s or "BROWSER" in s:
                return True

            # enum name check
            name = getattr(cfg, "name", "")
            if isinstance(name, str) and ("PLAY" in name.upper() or "PW" == name.upper()):
                return True

        except Exception:
            return False

        return False

    def _choose_playwright_url(self) -> str:
        """
        Prefer seed_url if present, else base_url, else empty.
        (Model can also navigate internally; this is just best-effort.)
        """
        url = ""
        try:
            url = getattr(self.model, "seed_url", "") or ""
        except Exception:
            url = ""

        if url:
            return url

        try:
            base = getattr(self.model, "base_url", "") or ""
        except Exception:
            base = ""

        if base:
            # Good default for Pastebin-like sources; harmless for others
            return base.rstrip("/") + "/archive"

        return ""

    def _attach_playwright_page_to_model(self, page: Any) -> None:
        """
        Attach Playwright Page in multiple standard places.
        Only sets attributes; does NOT remove anything.
        """
        if not self.model:
            return

        # Preferred if model supports it
        if hasattr(self.model, "attach_page"):
            try:
                self.model.attach_page(page)
                return
            except Exception:
                pass

        # Fallback attribute names
        for attr in (
            "_request_page",
            "page",
            "_page",
            "request_page",
            "playwright_page",
            "browser_page",
            "pw_page",
        ):
            try:
                setattr(self.model, attr, page)
            except Exception:
                pass

    def _wants_tor_proxy(self) -> bool:
        """Check if model's rule_config requests Tor proxy."""
        try:
            rule = getattr(self.model, "rule_config", None)
            if rule is None:
                return False
            fp = getattr(rule, "m_fetch_proxy", None)
            if fp is None:
                return False
            return str(fp).upper().endswith("TOR") or getattr(fp, "name", "") == "TOR"
        except Exception:
            return False

    def _run_with_playwright(self) -> Any:
        """
        Create Playwright Page, attach to model, call model.run(page) with fallback.
        Only called when _wants_playwright() is True.
        Passes Tor proxy when model's rule_config requests FetchProxy.TOR.
        """
        if sync_playwright is None:
            raise RuntimeError(
                "Playwright not available but model.rule_config.m_fetch_config=PLAYWRIGHT"
            )

        url = self._choose_playwright_url()

        # Build Playwright launch kwargs — include proxy for Tor/.onion scrapers
        launch_kwargs = {"headless": self.playwright_headless}
        if self._wants_tor_proxy() and self.proxy:
            server = self.proxy.get("server", "")
            if server:
                launch_kwargs["proxy"] = {"server": server}
                print(f"[RequestParser][PLAYWRIGHT] Launching with Tor proxy: {server}")

        with sync_playwright() as p:
            browser = p.chromium.launch(**launch_kwargs)
            context = browser.new_context(ignore_https_errors=True)
            try:
                page = context.new_page()

                if url:
                    try:
                        page.goto(url, wait_until="domcontentloaded", timeout=self.playwright_timeout)
                    except Exception as ex:
                        # Do not hard fail; model may navigate itself
                        print(f"[RequestParser][PLAYWRIGHT] goto failed (non-fatal): {ex}")

                # Attach page to model
                self._attach_playwright_page_to_model(page)

                # Try run(page), run(), parse_leak_data(page) — whichever the model supports
                try:
                    return self.model.run(page)
                except (TypeError, AttributeError):
                    pass
                except Exception as e:
                    # Catch nested sync_playwright error from models that
                    # manage their own browser
                    if "Sync API" in str(e) and "asyncio" in str(e):
                        print(f"[RequestParser][PLAYWRIGHT] model.run(page) nested sync_playwright detected — will retry outside wrapper")
                        raise  # caught by outer handler below

                try:
                    return self.model.run()
                except AttributeError:
                    pass
                except Exception as e:
                    if "Sync API" in str(e) and "asyncio" in str(e):
                        print(f"[RequestParser][PLAYWRIGHT] model.run() nested sync_playwright detected — will retry outside wrapper")
                        raise

                # Old-style leak scrapers only have parse_leak_data(page)
                if hasattr(self.model, "parse_leak_data"):
                    return self.model.parse_leak_data(page)

                raise RuntimeError(f"Model {self.model.__class__.__name__} has no run() or parse_leak_data()")
            finally:
                try:
                    context.close()
                except Exception:
                    pass
                try:
                    browser.close()
                except Exception:
                    pass

    def parse(self) -> Dict[str, Any]:
        start_time = time.time()

        meta = {
            "source": self.model.__class__.__name__ if self.model else None,
            "status": "failed",
            "count": 0,
            "duration": 0.0,
            "error": None,
        }

        print(f"[RequestParser] ▶ Starting parser for {meta['source']}")

        if not self.model:
            meta["error"] = "No model provided"
            print("[RequestParser] ❌ No model provided")
            return {"meta": meta, "data": []}

        try:
            if self.reset_cache and hasattr(self.model, "reset_cache"):
                print("[RequestParser] Resetting model cache")
                self.model.reset_cache()

            if self.proxy and hasattr(self.model, "set_proxy"):
                print(f"[RequestParser] Using proxy: {self.proxy}")
                self.model.set_proxy(self.proxy)

            # ✅ OPT-IN seed fetch:
            # - either RequestParser(seed_fetch=True)
            # - or model.needs_seed_fetch = True
            needs_seed = bool(getattr(self.model, "needs_seed_fetch", False))
            if self.seed_fetch or needs_seed:
                try:
                    self._requests_fetch_seed()
                except Exception as ex:
                    # don't break other scripts; just log
                    print(f"[RequestParser][SEED_FETCH] ❌ failed: {ex}")

            print("[RequestParser] Running model.run() …")

            # =========================
            # ✅ ADD: Playwright path (ONLY when explicitly configured)
            # =========================
            if self._wants_playwright():
                # If the model has its own _run_playwright() method, it manages its
                # own sync_playwright() context.  Wrapping it in ANOTHER
                # sync_playwright() causes "Sync API inside asyncio loop" errors.
                # → run the model directly and skip the outer wrapper.
                if hasattr(self.model, '_run_playwright'):
                    print("[RequestParser] Model has own _run_playwright — calling model.run() directly")
                    raw_result = self.model.run()
                else:
                    try:
                        raw_result = self._run_with_playwright()
                    except Exception as pw_err:
                        if "Sync API" in str(pw_err) and "asyncio" in str(pw_err):
                            print("[RequestParser] Nested sync_playwright detected — retrying model.run() outside wrapper")
                            raw_result = self.model.run()
                        else:
                            raise
            else:
                # ✅ keep existing behavior exactly
                raw_result = self.model.run()

            data = self._validate_output(raw_result)

            # If run()/parse_leak_data() stored items internally, include them
            if not data and hasattr(self.model, 'card_data') and self.model.card_data:
                for card in self.model.card_data:
                    if hasattr(card, 'to_dict'):
                        data.append(card.to_dict())
                    elif hasattr(card, '__dict__'):
                        data.append(card.__dict__)
                    elif isinstance(card, dict):
                        data.append(card)

            meta["status"] = "success"
            meta["count"] = len(data)

            return {"meta": meta, "data": data}

        except Exception as e:
            meta["error"] = str(e)
            print("[RequestParser] ❌ Exception occurred")
            traceback.print_exc()

            if self.strict:
                raise

            return {"meta": meta, "data": []}

        finally:
            meta["duration"] = round(time.time() - start_time, 2)
            print(
                f"[RequestParser] ✔ Finished {meta['source']} | "
                f"status={meta['status']} | "
                f"items={meta['count']} | "
                f"time={meta['duration']}s"
            )
