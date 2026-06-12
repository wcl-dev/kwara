"""Network sub-tab — redirect chain, TLS certificate, response headers."""
import json

import pandas as pd
import streamlit as st

from i18n import t
from views._shared import fetch_evidence_rows, url_selector


def render(conn, case_id):
    st.caption(t("net.help"))

    rows = fetch_evidence_rows(conn, case_id)
    scanned = [r for r in rows if r["scan_status"] == "done"]
    has_tls = sum(1 for r in scanned if r["sr_tls_info_json"])

    m1, m2, m3 = st.columns(3)
    m1.metric(t("net.scanned"), len(scanned))
    m2.metric(t("net.with_tls"), has_tls)
    m3.metric(t("net.pending"), len(rows) - len(scanned))

    if not scanned:
        st.info(t("net.scan_first"))
        return

    st.divider()
    sel = url_selector(rows, key_suffix="_net")

    if not sel["scan_run_id"] or sel["scan_status"] != "done":
        st.info(t("net.not_scanned"))
        return

    # ── Redirect Chain ──────────────────────────────────────────
    st.subheader(t("net.chain"))
    st.caption(t("net.chain_caption", final=sel["final_url"] or "—", hops=sel["hop_count"] or 0))
    hops = conn.execute(
        "SELECT hop_order, url, status_code, location FROM redirect_hops WHERE scan_run_id = ? ORDER BY hop_order",
        (sel["scan_run_id"],),
    ).fetchall()
    if hops:
        st.dataframe(pd.DataFrame([dict(h) for h in hops]), width='stretch', hide_index=True)

    # ── TLS Certificate ─────────────────────────────────────────
    try:
        _tls_raw = sel["sr_tls_info_json"]
    except (IndexError, KeyError):
        _tls_raw = None

    st.subheader(t("net.tls"))
    if _tls_raw:
        _tls = json.loads(_tls_raw)
        _issuer = _tls.get("issuer", {})
        _subject = _tls.get("subject", {})
        c1, c2 = st.columns(2)
        with c1:
            st.write(t("net.tls_issuer", v=_issuer.get("commonName") or _issuer.get("organizationName") or "—"))
            st.write(t("net.tls_subject", v=_subject.get("commonName") or "—"))
            st.write(t("net.tls_serial", v=_tls.get("serialNumber") or "—"))
        with c2:
            st.write(t("net.tls_valid", start=_tls.get("notBefore") or "—", end=_tls.get("notAfter") or "—"))
            _san = _tls.get("subjectAltName", [])
            if _san:
                st.write(t("net.tls_san", v=", ".join(_san)))
    else:
        st.caption(t("net.no_tls"))

    # ── Response Headers ────────────────────────────────────────
    try:
        _hdrs_raw = sel["sr_headers_json"]
    except (IndexError, KeyError):
        _hdrs_raw = None

    st.subheader(t("net.headers"))
    if _hdrs_raw:
        _hdrs = json.loads(_hdrs_raw)
        st.caption(t("net.headers_count", n=len(_hdrs)))
        st.dataframe(
            pd.DataFrame(_hdrs, columns=["Header", "Value"]),
            width='stretch', hide_index=True,
        )
    else:
        st.caption(t("net.no_headers"))

    # ── ads.txt monetisation (Phase 8) — per-domain, regardless of grouping ──
    _ads_row = conn.execute(
        "SELECT ads_txt_json FROM scan_runs WHERE id = ?", (sel["scan_run_id"],)
    ).fetchone()
    _ads_raw = _ads_row["ads_txt_json"] if _ads_row else None

    st.subheader(t("net.ads_txt"))
    if _ads_raw:
        _ads = json.loads(_ads_raw)
        _recs = _ads.get("records") or []
        _direct = [r for r in _recs if (r.get("relationship") or "").upper() == "DIRECT"]
        st.caption(t("net.ads_txt_summary", status=_ads.get("status") or "—",
                     n=len(_recs), direct=len(_direct)))
        _owner, _mgr = _ads.get("owner_domain"), _ads.get("manager_domain")
        if _owner or _mgr:
            st.caption(t("net.ads_txt_declared", owner=_owner or "—", manager=_mgr or "—"))
        if _direct:
            st.dataframe(
                pd.DataFrame(
                    [{"Ad System": r.get("adsystem"),
                      "Seller ID": r.get("seller_id"),
                      "Cert Auth ID": r.get("cert_authority_id") or "—"}
                     for r in _direct],
                ),
                width='stretch', hide_index=True,
            )
    else:
        st.caption(t("net.no_ads_txt"))
