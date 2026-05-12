#!/usr/bin/env bash
# 從 0510revised.md 產出 0510revised.pdf
#
# 用法：
#   ./qsh_pdf/build-pdf.sh             # 只重出 PDF（圖不變）
#   ./qsh_pdf/build-pdf.sh --charts    # 先重編所有 mermaid 圖再出 PDF
#
# 工具鏈：
#   pandoc           Markdown → HTML（含 base64 內嵌所有圖片，避免相對路徑問題）
#   weasyprint       HTML → PDF（margin、CJK 字型、表格樣式都靠它）
#   @mermaid-js/mermaid-cli (mmdc)   .mmd → .png（僅 --charts 模式需要）
#
# 注意：各 mermaid 圖的尺寸有 case-by-case 調整（chart_3 / chart_4 / chart_5
# 都用過不同 -w/-H），預設 --charts 會用統一尺寸重編，可能破壞既有比例。
# 若只想單獨重編一張圖，請手動跑 mmdc 並指定該圖原本的 -w/-H。

set -euo pipefail

# 切到 repo root（不論 script 從哪裡被叫）
KWARA_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$KWARA_ROOT"

CHARTS_DIR="qsh_pdf/charts"
MD_FILE="0510revised.md"
PDF_FILE="0510revised.pdf"
CSS_FILE="qsh_pdf/pdf-style.css"

# 可選：重編所有 mermaid 圖
if [[ "${1:-}" == "--charts" ]]; then
    echo "▶ 重編所有 mermaid 圖（統一尺寸 1200x1000）..."
    for mmd in "$CHARTS_DIR"/*.mmd; do
        png="${mmd%.mmd}.png"
        printf "  %-40s → %s\n" "$(basename "$mmd")" "$(basename "$png")"
        mmdc -i "$mmd" -o "$png" -w 1200 -H 1000 --backgroundColor white
    done
    echo "  ⚠ 若某張圖比例需要調整，手動跑 mmdc 並覆蓋該 PNG"
fi

# 主步驟：md → PDF（pipe，無中間檔）
echo "▶ 匯出 PDF: $MD_FILE → $PDF_FILE"
pandoc "$MD_FILE" \
    --embed-resources --standalone \
    -c "$CSS_FILE" \
    -t html \
    | weasyprint - "$PDF_FILE" 2>&1 \
    | grep -v "^WARNING:" || true   # weasyprint 對部分現代 CSS 有 warning，無害可略

# 報告結果
size=$(stat -f%z "$PDF_FILE" 2>/dev/null || stat -c%s "$PDF_FILE")
pages=$(mdls -name kMDItemNumberOfPages "$PDF_FILE" 2>/dev/null | awk '{print $3}')
printf "✔ 完成：%s（%d 頁，%.0f KB）\n" "$PDF_FILE" "${pages:-0}" "$(echo "$size / 1024" | bc)"
