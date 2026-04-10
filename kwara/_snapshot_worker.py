"""Standalone script invoked by snapshots._capture_in_subprocess.

Usage: python _snapshot_worker.py <input.json> <output.json>

JSON fields:
  urls: [...], timeout: int,
  mode: "headless_only" | "headed_only" (default: headless_only when omitted for backward compat — caller always passes explicitly)

Environment:
  KWARA_PLAYWRIGHT_PROXY or HTTPS_PROXY — proxy server URL for Playwright
  KWARA_BROWSER_LOCALE    — Playwright context locale (default: zh-TW)
  KWARA_BROWSER_TIMEZONE  — Playwright context timezone_id (default: Asia/Taipei)
  KWARA_BROWSER_LANGUAGES — comma-separated navigator.languages override
                            (default: derived from KWARA_BROWSER_LOCALE, e.g.
                             "zh-TW" -> "zh-TW,zh,en-US,en";
                             "en-GB" -> "en-GB,en")

Set these per case/victim locale so evidence reflects what the reporter actually
saw — many scam pages cloak content based on Accept-Language + geo IP, so a
Taipei-locale browser can produce misleading snapshots for an overseas report.
"""
import json
import os
import random
import shutil
import sys
import tempfile
import time
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright


_CF_SIGNALS = ("Just a moment", "Checking your browser", "Verify you are human",
               "challenge-platform", "正在執行安全驗證", "請稍候",
               "正在验证您的浏览器", "安全验证", "cf-turnstile-response")


def _resolve_languages(locale: str) -> list[str]:
    """Build a reasonable navigator.languages list from a BCP 47 locale tag.

    If KWARA_BROWSER_LANGUAGES is set, it wins (comma-separated).
    Otherwise derive a fallback chain: the locale itself, its primary subtag,
    and (for non-English locales) en-US/en as a common Accept-Language tail.
    """
    raw = os.environ.get("KWARA_BROWSER_LANGUAGES", "").strip()
    if raw:
        return [tag.strip() for tag in raw.split(",") if tag.strip()]

    primary = locale.split("-", 1)[0].lower() if locale else ""
    chain: list[str] = []
    if locale:
        chain.append(locale)
    if primary and primary != locale.lower():
        chain.append(primary)
    if primary != "en":
        chain.extend(["en-US", "en"])
    return chain


_BROWSER_LOCALE = os.environ.get("KWARA_BROWSER_LOCALE", "zh-TW").strip() or "zh-TW"
_BROWSER_TIMEZONE = os.environ.get("KWARA_BROWSER_TIMEZONE", "Asia/Taipei").strip() or "Asia/Taipei"
_BROWSER_LANGUAGES = _resolve_languages(_BROWSER_LOCALE)

_STEALTH_SCRIPT = """
    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
    Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
    Object.defineProperty(navigator, 'languages', {get: () => %s});
    window.chrome = {runtime: {}};
""" % json.dumps(_BROWSER_LANGUAGES)

_CONTEXT_OPTS = dict(
    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
               'AppleWebKit/537.36 (KHTML, like Gecko) '
               'Chrome/126.0.0.0 Safari/537.36',
    viewport={"width": 1280, "height": 800},
    locale=_BROWSER_LOCALE,
    timezone_id=_BROWSER_TIMEZONE,
)

_BROWSER_ARGS = ["--disable-blink-features=AutomationControlled"]


def _proxy_config():
    p = os.environ.get("KWARA_PLAYWRIGHT_PROXY") or os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
    if not p:
        return None
    return {"server": p.strip()}


def _apex(hostname: str) -> str:
    if not hostname:
        return ""
    parts = hostname.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def _is_cf_blocked(html: str) -> bool:
    snippet = html[:5000]
    return any(sig in snippet for sig in _CF_SIGNALS)


def _try_click_turnstile(page):
    try:
        for frame in page.frames:
            if "challenges.cloudflare.com" in (frame.url or ""):
                checkbox = frame.query_selector("input[type='checkbox']")
                if checkbox:
                    checkbox.click()
                    return True
                body = frame.query_selector("body")
                if body:
                    box = body.bounding_box()
                    if box:
                        frame.click("body", position={"x": box["width"] / 2,
                                                       "y": box["height"] / 2})
                        return True
    except Exception:
        pass
    return False


def _capture_page(browser, url, screenshot_path, html_path, timeout,
                  cf_wait_sec=6, try_turnstile_click=False, har_path=None):
    ctx_opts = dict(_CONTEXT_OPTS)
    if har_path:
        ctx_opts["record_har_path"] = har_path
        ctx_opts["record_har_url_filter"] = "**/*"
    context = browser.new_context(**ctx_opts)
    page = context.new_page()
    page.add_init_script(_STEALTH_SCRIPT)

    seen = set()
    domains = []

    def on_request(req, _seen=seen, _domains=domains):
        h = urlparse(req.url).hostname or ''
        if h and h not in _seen:
            _seen.add(h)
            _domains.append(h)

    page.on('request', on_request)

    page.goto(url, timeout=timeout * 1000, wait_until='domcontentloaded')

    for tick in range(cf_wait_sec):
        try:
            snippet = page.content()[:5000]
        except Exception:
            time.sleep(2)
            break
        if not any(sig in snippet for sig in _CF_SIGNALS):
            break
        if try_turnstile_click and tick == 3:
            _try_click_turnstile(page)
        time.sleep(1)

    try:
        page.wait_for_load_state('networkidle', timeout=8000)
    except Exception:
        pass

    page.screenshot(path=screenshot_path, full_page=True)

    try:
        html_content = page.content()
    except Exception:
        html_content = ""
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    context.close()
    return domains, html_content, None


def _run_headed_pass(pw, urls_info, timeout):
    """Headed Chrome persistent context for CF retries."""
    results_by_index = {}
    if not urls_info:
        return results_by_index

    user_data_dir = tempfile.mkdtemp(prefix="kwara_headed_")
    proxy = _proxy_config()
    launch_kw = dict(
        user_data_dir=user_data_dir,
        headless=False,
        channel="chrome",
        args=_BROWSER_ARGS + ["--window-position=-2400,-2400"],
        **_CONTEXT_OPTS,
    )
    if proxy:
        launch_kw["proxy"] = proxy

    context_headed = pw.chromium.launch_persistent_context(**launch_kw)
    context_headed.add_init_script(_STEALTH_SCRIPT)

    try:
        for ri, info in enumerate(urls_info):
            entry = {
                "scan_run_id": info["scan_run_id"],
                "screenshot_path": info["screenshot_path"],
                "html_path": info["html_path"],
                "request_domains": [],
                "error": None,
                "headed_retry": False,
            }
            idx = info.get("_batch_index", ri)
            try:
                page = context_headed.new_page()

                seen = set()
                req_domains = []

                def on_request(req, _seen=seen, _domains=req_domains):
                    h = urlparse(req.url).hostname or ''
                    if h and h not in _seen:
                        _seen.add(h)
                        _domains.append(h)

                page.on('request', on_request)

                os.makedirs(os.path.dirname(info["screenshot_path"]), exist_ok=True)
                page.goto(info["final_url"], timeout=timeout * 1000,
                          wait_until='domcontentloaded')

                for tick in range(25):
                    try:
                        snippet = page.content()[:5000]
                    except Exception:
                        time.sleep(2)
                        break
                    if not any(sig in snippet for sig in _CF_SIGNALS):
                        break
                    if tick == 3:
                        _try_click_turnstile(page)
                    time.sleep(1)

                try:
                    page.wait_for_load_state('networkidle', timeout=8000)
                except Exception:
                    pass

                page.screenshot(path=info["screenshot_path"], full_page=True)

                try:
                    html_content = page.content()
                except Exception:
                    html_content = ""
                with open(info["html_path"], 'w', encoding='utf-8') as hf:
                    hf.write(html_content)

                entry["request_domains"] = req_domains
                if _is_cf_blocked(html_content):
                    entry["error"] = "cf_blocked_after_headed_retry"

                page.close()

            except Exception as exc:
                entry["error"] = f"{type(exc).__name__}: {exc}"[:300] or "unknown error"
                entry["screenshot_path"] = None
                entry["html_path"] = None

            results_by_index[idx] = entry

            if ri < len(urls_info) - 1:
                time.sleep(random.uniform(3, 7))

    finally:
        context_headed.close()
        try:
            shutil.rmtree(user_data_dir, ignore_errors=True)
        except Exception:
            pass

    return results_by_index


def main():
    input_file = sys.argv[1]
    result_file = sys.argv[2]

    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    urls_info = data["urls"]
    timeout = data.get("timeout", 30)
    mode = data.get("mode", "headless_only")

    pw = sync_playwright().start()
    proxy = _proxy_config()
    launch_kw = dict(headless=True, args=_BROWSER_ARGS)
    if proxy:
        launch_kw["proxy"] = proxy

    results = []

    try:
        if mode == "headed_only":
            for i, info in enumerate(urls_info):
                if "_batch_index" not in info:
                    info["_batch_index"] = i
            merged = _run_headed_pass(pw, urls_info, timeout)
            results = [merged[info["_batch_index"]] for info in urls_info]
        else:
            # headless_only
            browser_headless = pw.chromium.launch(**launch_kw)
            last_apex = None

            try:
                for i, info in enumerate(urls_info):
                    entry = {
                        "scan_run_id": info["scan_run_id"],
                        "screenshot_path": info["screenshot_path"],
                        "html_path": info["html_path"],
                        "request_domains": [],
                        "error": None,
                        "headed_retry": False,
                    }
                    host = urlparse(info["final_url"]).hostname or ""
                    apex = _apex(host)
                    if last_apex and apex == last_apex:
                        time.sleep(random.uniform(5, 15))
                    last_apex = apex

                    try:
                        _snap_dir = os.path.dirname(info["screenshot_path"])
                        os.makedirs(_snap_dir, exist_ok=True)
                        _har = os.path.join(_snap_dir, "traffic.har")
                        domains, html, _ = _capture_page(
                            browser_headless, info["final_url"],
                            info["screenshot_path"], info["html_path"], timeout,
                            har_path=_har,
                        )
                        entry["request_domains"] = domains
                        entry["har_path"] = _har if os.path.exists(_har) else None

                        if _is_cf_blocked(html):
                            time.sleep(random.uniform(35, 55))
                            domains, html, _ = _capture_page(
                                browser_headless, info["final_url"],
                                info["screenshot_path"], info["html_path"], timeout,
                                har_path=_har,
                            )
                            entry["request_domains"] = domains
                            entry["har_path"] = _har if os.path.exists(_har) else None

                        if _is_cf_blocked(html):
                            entry["headed_retry"] = True

                    except Exception as exc:
                        entry["error"] = f"{type(exc).__name__}: {exc}"[:300] or "unknown error"
                        entry["screenshot_path"] = None
                        entry["html_path"] = None

                    results.append(entry)

                    if i < len(urls_info) - 1:
                        time.sleep(random.uniform(2, 5))

            finally:
                browser_headless.close()

    finally:
        pw.stop()

    with open(result_file, 'w', encoding='utf-8') as f:
        json.dump(results, f)


if __name__ == "__main__":
    main()
