"""kwara/_snapshot_worker.py — 224 statements that nothing had ever executed.

It is launched BY PATH as a subprocess (snapshots._capture_in_subprocess),
imports nothing from kwara so it survives being run as a bare script, and ships
as package-data. That combination makes it the code path a packaging change is
most likely to break and least likely to break loudly: a missing file or a bad
import surfaces as "no result file" much later, on a machine doing real work.

Contract, read from snapshots.py:
    argv[1] = input JSON  {"urls": [...], "timeout": int, "mode": str}
    argv[2] = path to write the result JSON
"""
import json
import os
import shutil
import subprocess
import sys

import pytest

from kwara import snapshots

WORKER = os.path.join(os.path.dirname(os.path.abspath(snapshots.__file__)),
                      "_snapshot_worker.py")


def _has_chromium() -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return False
    try:
        with sync_playwright() as p:
            path = p.chromium.executable_path
        return bool(path) and os.path.exists(path)
    except Exception:
        return False


browser = pytest.mark.skipif(
    not _has_chromium(),
    reason="chromium not installed; run `playwright install chromium`")


def _run_worker(payload, tmp_path, env=None, timeout=120):
    in_file = tmp_path / "in.json"
    out_file = tmp_path / "out.json"
    in_file.write_text(json.dumps(payload), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, WORKER, str(in_file), str(out_file)],
        capture_output=True, text=True, timeout=timeout,
        env=dict(os.environ, **(env or {})))
    result = None
    if out_file.exists():
        result = json.loads(out_file.read_text(encoding="utf-8"))
    return proc, result


# ── the file itself ────────────────────────────────────────────────────────

def test_worker_ships_where_snapshots_looks_for_it():
    """snapshots.py builds the path from its own __file__. If packaging drops
    the worker, capture fails only at runtime on an installed copy."""
    assert os.path.isfile(WORKER)


def test_worker_imports_nothing_from_kwara():
    """It runs as a bare script with no package context. A relative import
    would raise 'attempted relative import with no known parent package' — the
    exact failure that broke two other scripts during the package refactor."""
    src = open(WORKER, encoding="utf-8").read()
    assert "from ." not in src
    for mod in ("config", "db", "snapshots", "scanner", "kwara"):
        assert f"import {mod}" not in src, mod


def test_worker_compiles_standalone():
    proc = subprocess.run([sys.executable, "-m", "py_compile", WORKER],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


# ── failure modes, no browser needed ───────────────────────────────────────

def test_missing_arguments_fail_loudly_not_silently(tmp_path):
    """snapshots.py treats a missing result file as an error, so the worker may
    exit non-zero — but it must not hang, and it must say something."""
    proc = subprocess.run([sys.executable, WORKER], capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode != 0
    assert (proc.stderr or proc.stdout).strip()


def test_unreadable_input_produces_an_error_not_a_hang(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    out = tmp_path / "out.json"
    proc = subprocess.run([sys.executable, WORKER, str(bad), str(out)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode != 0 or out.exists()


def test_empty_url_list_is_handled(tmp_path):
    proc, result = _run_worker({"urls": [], "timeout": 5, "mode": "screenshot"},
                               tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert result == [] or result is not None


# ── real captures ──────────────────────────────────────────────────────────

@pytest.mark.browser
@browser
def test_captures_screenshot_and_html_from_a_live_page(site, tmp_path):
    site.route("/p", body="<html><head><title>T</title></head>"
                          "<body><h1>hello</h1></body></html>")
    shot = tmp_path / "screenshot.png"
    html = tmp_path / "page.html"
    proc, result = _run_worker({
        "urls": [{"scan_run_id": 1, "final_url": site.url_for("/p"),
                  "screenshot_path": str(shot), "html_path": str(html)}],
        "timeout": 30, "mode": "screenshot"}, tmp_path)

    assert proc.returncode == 0, proc.stderr[:800]
    assert result, proc.stderr[:800]
    assert shot.exists() and shot.stat().st_size > 0
    assert html.exists() and "hello" in html.read_text(encoding="utf-8")


@pytest.mark.browser
@browser
def test_javascript_injected_ids_are_visible_to_the_browser_only(site, tmp_path):
    """The whole justification for Playwright existing. A GA4 loaded through
    GTM is absent from the static HTML and present after JS runs; if this stops
    holding, the expensive capture step buys nothing over `run attribute`."""
    site.route("/gtm.js", body="window.dataLayer=window.dataLayer||[];"
                               "document.body.innerHTML+="
                               "\"<span id=late>G-JSONLY0001</span>\";",
               headers={"Content-Type": "application/javascript"})
    site.route("/p", body='<html><body><script src="/gtm.js"></script></body></html>')

    html = tmp_path / "page.html"
    proc, result = _run_worker({
        "urls": [{"scan_run_id": 1, "final_url": site.url_for("/p"),
                  "screenshot_path": str(tmp_path / "s.png"),
                  "html_path": str(html)}],
        "timeout": 30, "mode": "screenshot"}, tmp_path)
    assert proc.returncode == 0, proc.stderr[:800]
    assert "G-JSONLY0001" in html.read_text(encoding="utf-8"), (
        "the rendered HTML did not contain the JS-injected ID")


@pytest.mark.browser
@browser
def test_browser_locale_env_vars_reach_the_page(site, tmp_path):
    """kwara claims a capture reconstructs what a victim in a given region
    would have seen. That rests entirely on these two variables reaching
    Playwright, and nothing verified it."""
    site.route("/loc", body="<html><body><div id=out></div><script>"
                            "document.getElementById('out').textContent="
                            "navigator.language;</script></body></html>")
    html = tmp_path / "page.html"
    proc, _ = _run_worker({
        "urls": [{"scan_run_id": 1, "final_url": site.url_for("/loc"),
                  "screenshot_path": str(tmp_path / "s.png"),
                  "html_path": str(html)}],
        "timeout": 30, "mode": "screenshot"},
        tmp_path, env={"KWARA_BROWSER_LOCALE": "ja-JP",
                       "KWARA_BROWSER_TIMEZONE": "Asia/Tokyo"})
    assert proc.returncode == 0, proc.stderr[:800]
    assert "ja" in html.read_text(encoding="utf-8").lower()


@pytest.mark.browser
@browser
def test_a_challenge_page_is_captured_rather_than_discarded(site, tmp_path):
    """A 403 interstitial is evidence: it shows the operator is gating. The
    capture must record it, not treat it as nothing happened."""
    from fixtures.server import page_bytes
    site.route("/blocked", status=403, body=page_bytes("challenge_403.html"))
    html = tmp_path / "page.html"
    proc, result = _run_worker({
        "urls": [{"scan_run_id": 1, "final_url": site.url_for("/blocked"),
                  "screenshot_path": str(tmp_path / "s.png"),
                  "html_path": str(html)}],
        "timeout": 30, "mode": "screenshot"}, tmp_path)
    assert proc.returncode == 0, proc.stderr[:800]
    assert result is not None
