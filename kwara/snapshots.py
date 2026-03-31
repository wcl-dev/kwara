import json
import os
import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlparse

from audit import write_audit
from clustering import KNOWN_SHORTLINK_DOMAINS

SUSPICIOUS_EXTS = {'.exe', '.zip', '.apk', '.dmg', '.msi', '.bat', '.sh', '.ps1', '.jar', '.rar', '.7z'}

TRACKER_DOMAINS = {
    'google-analytics.com', 'googletagmanager.com', 'facebook.net',
    'doubleclick.net', 'googlesyndication.com', 'hotjar.com',
    'mixpanel.com', 'segment.com', 'amplitude.com', 'clarity.ms',
    'adnxs.com', 'taboola.com', 'outbrain.com',
}

HIGH_TRACKER_THRESHOLD = 3


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _apex(hostname: str) -> str:
    parts = hostname.split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else hostname


def _risk_tags(final_url: str, hop_count: int, request_domains: list) -> list:
    tags = []
    parsed = urlparse(final_url)

    if hop_count >= 3:
        tags.append('multi_hop')

    path = parsed.path.lower()
    if any(path.endswith(ext) for ext in SUSPICIOUS_EXTS):
        tags.append('suspicious_download')

    if parsed.scheme == 'http':
        tags.append('no_https')

    if (parsed.hostname or "") in KNOWN_SHORTLINK_DOMAINS:
        tags.append('url_shortener_chain')

    apexes = {_apex(d) for d in request_domains if d}
    if len(apexes & TRACKER_DOMAINS) >= HIGH_TRACKER_THRESHOLD:
        tags.append('high_tracker_count')

    return tags


def snapshot_url(conn: sqlite3.Connection, scan_run_id: int, timeout: int = 30) -> int:
    from playwright.sync_api import sync_playwright

    row = conn.execute(
        """SELECT sr.final_url, sr.hop_count, ua.case_id, ua.id AS url_artifact_id
           FROM scan_runs sr
           JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
           WHERE sr.id = ?""",
        (scan_run_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"scan_run_id {scan_run_id} not found")

    final_url    = row['final_url']
    hop_count    = row['hop_count'] or 0
    case_id      = row['case_id']
    final_domain = urlparse(final_url).hostname or ''

    base_dir        = os.path.join(os.path.dirname(__file__), 'data', 'snapshots', str(scan_run_id))
    os.makedirs(base_dir, exist_ok=True)
    screenshot_path = os.path.join(base_dir, 'screenshot.png')
    html_path       = os.path.join(base_dir, 'page.html')

    request_domains = []
    error_note      = None

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent='Mozilla/5.0 (compatible; kwara-scanner/1.0)',
            )
            page = context.new_page()

            seen = set()
            def on_request(req):
                h = urlparse(req.url).hostname or ''
                if h and h not in seen:
                    seen.add(h)
                    request_domains.append(h)

            page.on('request', on_request)
            page.goto(final_url, timeout=timeout * 1000, wait_until='domcontentloaded')
            page.screenshot(path=screenshot_path, full_page=True)

            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(page.content())

            browser.close()

    except Exception as exc:
        error_note      = str(exc)[:300]
        screenshot_path = None
        html_path       = None

    tags = _risk_tags(final_url, hop_count, request_domains)
    if error_note:
        tags.insert(0, 'capture_error')

    conn.execute(
        """INSERT INTO snapshots
               (scan_run_id, final_url, final_domain,
                screenshot_path, html_path,
                request_domains_json, risk_tags, captured_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            scan_run_id, final_url, final_domain,
            screenshot_path, html_path,
            json.dumps(request_domains),
            json.dumps(tags),
            _now(),
        ),
    )
    conn.commit()
    snapshot_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    write_audit(
        conn,
        'snapshot_url',
        case_id=case_id,
        meta={
            'scan_run_id':          scan_run_id,
            'snapshot_id':          snapshot_id,
            'final_url':            final_url,
            'final_domain':         final_domain,
            'hop_count':            hop_count,
            'risk_tags':            tags,
            'request_domain_count': len(request_domains),
            'error':                error_note,
        },
    )

    return snapshot_id
