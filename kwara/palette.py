"""繪圖用的色票（單一事實來源）。

原本是 Streamlit UI 的 design token，與 .streamlit/config.toml 的 [theme]
同步維護。UI 於 2026-08-07 移除後，留下的是 `graph.py` 的關聯圖與
`clusters.py` 的群組標色——兩者都由 CLI 使用，與介面無關。

原則不變：紅色保留給真正的警示，不得用於選取、識別碼或群組標示；
強調一律用 ACCENT 藍。群組色刻意克制、傾向色盲友善。
"""

ACCENT = "#1D4ED8"        # 唯一強調藍：判定標題、主要徽章、連結
INK = "#111111"           # 近黑文字 / 黑色徽章
MUTED = "#6B7280"         # 次要文字（計數、說明）
FAINT = "#9CA3AF"         # 最弱層級（欄位標籤）
NEUTRAL_FILL = "#F5F5F5"  # 中性底（graphviz 節點、卡片底）
BORDER = "#D9D9D9"
GRAPH_EDGE = "#C4C4C4"    # 關聯圖邊線

# 群組分類色：克制、色盲友善傾向；群組 1 = ACCENT 與全 UI 同調
GROUP_PALETTE = [
    "#1D4ED8",  # blue (= ACCENT)
    "#0E7490",  # teal
    "#7C3AED",  # violet
    "#B45309",  # dark amber
    "#111111",  # ink
    "#15803D",  # green
    "#BE185D",  # magenta（僅在前六色用罄時出現）
    "#4D7C0F",  # olive
]
