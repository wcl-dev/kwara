"""Cross-case page (group-centric rebuild) — made comprehensible.

The old cross-case tab dumped raw rows ("[tracking_id] G-T5N9K2Q7W3 — 2 cases")
that nobody could read. This rewrite tells the actual story: the SAME
fingerprint showing up in DIFFERENT cases means the cases may share one
operator. Plain-language type labels, strong signals first, the noisy ones
(ads.txt accounts — content farms share ad networks) tucked away.
"""
import streamlit as st

from config import DB_PATH, INDEX_DB_PATH
from index_db import get_index_conn, index_case, lookup, recurring_signals

# type → (plain label, what it means, is it a strong same-operator signal)
_TYPE = {
    "tracking_id":      ("追蹤帳號", "GA／Meta Pixel 等帳號，綁定單一註冊者——最強的「同一人」證據", True),
    "cert_serial":      ("TLS 加密憑證", "同一張憑證 = 同一台伺服器／同一批佈署", True),
    "ads_txt_template": ("ads.txt 模板", "逐字節完全相同的廣告授權檔 = 同一份模板複製出去", True),
    "final_domain":     ("落地域名", "同一個網域在多個案件出現", True),
    "ads_txt_seller":   ("ads.txt 廣告帳號", "廣告分潤帳號——**較弱**，內容農場常共用同一批廣告網路", False),
    "registrar":        ("網域註冊商", "弱訊號，僅供參考", False),
    "asn":              ("託管商 ASN", "弱訊號，僅供參考", False),
}


def _label(stype):
    return _TYPE.get(stype, (stype, "", False))[0]


def _cases_str(cases):
    seen, names = set(), []
    for c in cases:
        nm = (c["case_title"] or f"#{c['case_id']}")
        if nm not in seen:
            seen.add(nm); names.append(nm)
    return "、".join(names)


def render(conn, case_id):
    st.subheader("跨案件比對")
    st.caption(
        "同一個「數位指紋」如果在**不同案件**重複出現，代表這些案件背後可能是**同一個操作者**。"
        "這裡跨越你索引過的所有案件（含其他 kwara DB 檔）。"
    )

    try:
        idx = get_index_conn(INDEX_DB_PATH)
    except OSError as e:
        st.error(f"無法開啟跨案件索引：{e}")
        return

    # ── 1. Add the current case to the comparison ──────────────────────
    with st.container(border=True):
        st.markdown("**把這個案件納入比對**")
        st.caption("先把案件的指紋存進中央索引，才能跟其他案件互相比對。重覆按會更新。")
        if case_id is not None:
            title = conn.execute(
                "SELECT title FROM cases WHERE id = ?", (case_id,)
            ).fetchone()
            title = (title["title"] if title else "") or f"#{case_id}"
            if st.button(f"納入比對：{title}", key="xc_index"):
                n = index_case(idx, conn, DB_PATH, case_id, title)
                st.success(f"已納入「{title}」的 {n} 個指紋。")
        else:
            st.caption("（先在側欄選一個案件）")

    # ── 2. Fingerprints recurring across cases ─────────────────────────
    st.markdown("#### 跨案件重複出現的線索")
    rec = recurring_signals(idx, min_cases=2)
    if not rec:
        st.info(
            "目前沒有任何指紋跨越 2 個以上案件。把更多案件「納入比對」後，"
            "共同的操作者線索就會出現在這裡。"
        )
        return

    strong = [r for r in rec if _TYPE.get(r["signal_type"], (None, None, False))[2]]
    weak = [r for r in rec if not _TYPE.get(r["signal_type"], (None, None, False))[2]]

    st.caption(
        f"共 **{len(rec)}** 條指紋跨越 ≥2 案件"
        f"（{len(strong)} 條強訊號、{len(weak)} 條弱訊號）。強訊號先看。"
    )

    # strong signals, grouped by type (strongest types first)
    _order = ["tracking_id", "cert_serial", "ads_txt_template", "final_domain"]
    by_type = {}
    for r in strong:
        by_type.setdefault(r["signal_type"], []).append(r)
    for stype in _order:
        items = by_type.get(stype)
        if not items:
            continue
        label, meaning, _ = _TYPE[stype]
        st.markdown(f"##### {label}")
        st.caption(meaning)
        for r in sorted(items, key=lambda x: -x["case_count"]):
            plat = f" [{r['platform']}]" if r.get("platform") else ""
            st.markdown(
                f"- `{r['signal_value']}`{plat} — 出現在 **{r['case_count']} 個案件**："
                f"{_cases_str(r['cases'])}"
            )

    # weak signals tucked away
    if weak:
        with st.expander(f"弱訊號（{len(weak)} 條，僅供參考，易誤判）"):
            st.caption(
                "ads.txt 廣告帳號、註冊商、ASN 這類訊號，正常網站之間也常常一樣"
                "（內容農場共用廣告網路、大家都用 Cloudflare），不能單獨當作同一操作者的證據。"
            )
            for r in sorted(weak, key=lambda x: -x["case_count"]):
                plat = f" [{r['platform']}]" if r.get("platform") else ""
                st.markdown(
                    f"- {_label(r['signal_type'])}：`{r['signal_value']}`{plat} — "
                    f"{r['case_count']} 案：{_cases_str(r['cases'])}"
                )

    # ── 3. Look up one fingerprint ─────────────────────────────────────
    with st.expander("查一個指紋出現在哪些案件"):
        val = st.text_input("輸入追蹤碼／憑證序號／域名等", key="xc_lookup",
                            placeholder="例如 G-T5N9K2Q7W3")
        if val:
            hits = lookup(idx, val)
            if not hits:
                st.info(f"索引裡沒有任何案件含「{val}」。")
            else:
                st.write(f"「{val}」出現在 {len(hits)} 筆紀錄：")
                st.dataframe(
                    [{
                        "類型": _label(h["signal_type"]),
                        "平台": h["platform"] or "—",
                        "案件": h["case_title"] or f"#{h['case_id']}",
                        "域名": h["final_domain"] or "—",
                    } for h in hits],
                    hide_index=True, width="stretch",
                )
