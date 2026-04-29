"""Shared helpers used by multiple view modules."""
from __future__ import annotations

import json
import sqlite3
from urllib.parse import urlparse as _urlparse

from config import KNOWN_SHORTLINK_DOMAINS, SUSPICIOUS_EXTS as _SUSP_EXTS
from i18n import t
from param_attribution import (
    OWNER_KIND_GENERIC,
    OWNER_KIND_PLATFORM,
    PLATFORM_DISPLAY_NAMES,
)


def localize_owner(row: dict) -> str:
    """Translate clustering's owner_kind/platform_id into a user-facing label.

    Clustering returns language-agnostic identifiers (owner_kind enum +
    canonical platform_id). The view layer translates here so cached
    clustering results stay correct when the user switches language.
    """
    kind = row.get("owner_kind", "")
    if kind == OWNER_KIND_PLATFORM:
        pid = row.get("platform_id") or ""
        # Fall back to the raw platform_id if a new vendor is added without
        # a display-name registration — better than returning "" silently.
        return PLATFORM_DISPLAY_NAMES.get(pid, pid)
    if kind == OWNER_KIND_GENERIC:
        return t("param.unattributed_tracker")
    return t("param.unrecognized_platform")


def localize_purpose(row: dict) -> str:
    """Translate clustering's purpose_key into a user-facing label."""
    pk = row.get("purpose_key") or ""
    kind = row.get("owner_kind", "")
    if pk:
        return t(pk)
    if kind == OWNER_KIND_GENERIC:
        return t("param.unattributed_purpose")
    return t("param.unidentified")

TAG_COLORS = {
    "multi_hop":            "🔴",
    "no_https":             "🟡",
    "new_domain":           "🟡",
    "suspicious_download":  "🔴",
    "high_tracker_count":   "🟠",
    "url_shortener_chain":  "🟠",
    "capture_error":        "⚪",
}


def scan_flags(final_url: str | None, hop_count: int | None) -> list[str]:
    """Risk signals derivable from scan data alone, before snapshot."""
    flags = []
    fu = final_url or ""
    if not fu:
        return flags
    p = _urlparse(fu)
    if (hop_count or 0) >= 3:
        flags.append("multi_hop")
    if p.scheme == "http":
        flags.append("no_https")
    if any(p.path.lower().endswith(e) for e in _SUSP_EXTS):
        flags.append("suspicious_download")
    if (p.hostname or "") in KNOWN_SHORTLINK_DOMAINS:
        flags.append("url_shortener_chain")
    return flags


def merged_flags(r, *, _scan_flags_fn=scan_flags) -> list[str]:
    """Combine snapshot risk tags, scan-time flags, and intel tags."""
    if r["snapshot_id"]:
        return json.loads(r["snapshot_risk_tags"] or "[]")
    flags = list(_scan_flags_fn(r["final_url"], r["hop_count"]))
    try:
        intel = json.loads(r["sr_intel_risk_tags"] or "[]")
    except (ValueError, TypeError):
        intel = []
    for tag in intel:
        if tag not in flags:
            flags.append(tag)
    return flags


def fetch_evidence_rows(conn: sqlite3.Connection, case_id: int) -> list:
    """Master query joining url_artifacts → scan_runs → snapshots.

    Used by all evidence sub-tabs to show URL lists with progress.
    """
    return conn.execute(
        """SELECT ua.id AS ua_id, ua.original_url, ua.domain,
                  sr.id AS scan_run_id, sr.status AS scan_status,
                  sr.final_url, sr.hop_count,
                  sr.whois_registrar AS sr_whois_registrar,
                  sr.whois_creation_date AS sr_whois_creation_date,
                  sr.ip_address AS sr_ip_address,
                  sr.asn AS sr_asn,
                  sr.as_org AS sr_as_org,
                  sr.as_country AS sr_as_country,
                  sr.intel_risk_tags AS sr_intel_risk_tags,
                  sr.domain_enriched_at AS sr_domain_enriched_at,
                  sr.tls_info_json AS sr_tls_info_json,
                  sr.final_response_headers_json AS sr_headers_json,
                  sr.corroboration_json AS sr_corroboration_json,
                  sr.cloaking_signal_json AS sr_cloaking_signal_json,
                  s.id   AS snapshot_id,
                  s.risk_tags AS snapshot_risk_tags
           FROM url_artifacts ua
           LEFT JOIN scan_runs sr ON sr.url_artifact_id = ua.id
               AND sr.id = (SELECT id FROM scan_runs WHERE url_artifact_id = ua.id ORDER BY id DESC LIMIT 1)
           LEFT JOIN snapshots s ON s.scan_run_id = sr.id
               AND s.id = (SELECT id FROM snapshots WHERE scan_run_id = sr.id ORDER BY id DESC LIMIT 1)
           WHERE ua.case_id = ? ORDER BY ua.id""",
        (case_id,),
    ).fetchall()


def url_selector(rows, *, key_suffix: str = ""):
    """Render a URL selectbox and return the selected row.

    Shows scan/snapshot status icons and risk flag emojis.
    Remembers last selection via session_state.
    """
    import streamlit as st
    from i18n import t

    def _label(r):
        url_short = r["original_url"][:55] + ("…" if len(r["original_url"]) > 55 else "")
        scan_icon = "✅" if r["scan_status"] == "done" else ("⏳" if r["scan_status"] == "running" else "⬜")
        snap_icon = "📸" if r["snapshot_id"] else ""
        flags = merged_flags(r)
        flag_icons = " ".join(TAG_COLORS.get(f, "⚪") for f in flags) if flags else ""
        return f"{scan_icon}{snap_icon} {url_short}  {flag_icons}"

    sorted_rows = sorted(rows, key=lambda r: (len(merged_flags(r)), r["ua_id"]), reverse=True)
    _seen = set()
    unique = []
    for r in sorted_rows:
        if r["ua_id"] not in _seen:
            _seen.add(r["ua_id"])
            unique.append(r)
    label_map = {f"[{r['ua_id']}] {_label(r)}": r for r in unique}

    _preferred = st.session_state.get("inv_last_ua_id")
    _default = 0
    _keys = list(label_map.keys())
    if _preferred:
        for i, k in enumerate(_keys):
            if label_map[k]["ua_id"] == _preferred:
                _default = i
                break

    sel = label_map[st.selectbox(
        t("url.select"), _keys, index=_default, key=f"url_sel{key_suffix}",
    )]
    return sel
