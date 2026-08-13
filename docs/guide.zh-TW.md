**[English](guide.md)**

# kwara — 辦一個案子

kwara 是本地端的操作者歸因與數位證據工具，特化於數位廣告生態：從可疑 URL 蒐集、掃描並佐證證據，再沿變現與測量訊號把背後的網站聚合成操作者群組。全部資料存在本機 SQLite。

這份文件講**怎麼辦一個案子**——動作的順序與判斷。逐一指令的完整參考在 [agent-interface.md](agent-interface.md)，演算法原理在 [analysis-design.md](analysis-design.md)。

kwara 沒有圖形介面，全部透過 CLI 或 MCP 操作。

---

## 安裝

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
python -m pip install -e .          # 或：-r requirements.txt
python -m playwright install chromium
```

`pip install -e .` 會把 `kwara` 指令裝到 PATH；沒安裝的話，下面每個指令都可以
在 repo 根目錄用 `python -m kwara.cli ...` 執行。

沒裝 Playwright／Chromium 也能用——掃描、WHOIS、ads.txt、歸因分析都不需要瀏覽器，只有截圖需要。

---

## 資料模型

```
cases（案件）
  └─ message_evidence（來源貼文）
        └─ url_artifacts（擷取的 URL）
              └─ scan_runs（redirect chain、TLS、headers、WHOIS/ASN、ads.txt、佐證）
                    ├─ redirect_hops（每一跳，含完整 response headers）
                    └─ snapshots（截圖、HTML、HAR、風險旗標）
```

案件彼此獨立。唯一橫跨案件的是**跨案件索引**（`~/.kwara/index.db`），它記住訊號出現過的地方——甚至橫跨不同的資料庫檔案。

---

## 一件案子的順序

```bash
kwara case new --title "夜鶯專案" --locale-preset tw
kwara ingest url --case 1 https://suspicious.example/x
kwara run attribute --case 1
kwara analyze clusters --case 1
```

`run attribute` 是**免瀏覽器的輕量歸因**：追跳轉、抓 TLS 與 headers、抓 ads.txt、查 WHOIS、抽靜態 HTML 裡的追蹤碼。

> **進件後不必急著截圖。** 輕量歸因通常已經足夠讓操作者群組浮現。截圖成本高得多，它補的是 **JS 動態注入的追蹤碼**（例如透過 GTM 載入的 GA4）與保全用的頁面證據。

要那些的時候：

```bash
kwara run snapshot --case 1          # Playwright：截圖 + HTML + HAR
kwara run corroborate --case 1       # Wayback、urlscan、RFC 3161 時間戳
```

**兩條擷取路徑都要跑，OPSEC 判定才成立。** 它比較的是「免瀏覽器」與「開瀏覽器」的成功率差異，用來揭露「擋爬蟲、放瀏覽器」的 WAF 部署。只跑其中一條，每個網域都會是 `indeterminate`——`analyze insights` 的 gaps 會告訴你缺哪一條。

---

## 讀結果

```bash
kwara analyze insights --case 1      # 規則式摘要：判定、發現、證據缺口
kwara analyze clusters --case 1      # 操作者群組與串起它們的訊號
kwara analyze narrative --case 1     # 白話判定
kwara analyze graph --case 1 --out graph.svg
```

**先看 `insights` 的 gaps。** 它會列出還沒蒐集的東西——沒做第三方佐證、沒有 TLS 紀錄、OPSEC 缺哪條路徑。空的分析結果多半代表沒蒐集，不代表沒發現。

證據力不是等價的。`analysis-design.md` 有完整分層，但實務上的順序是：

1. **逐字節相同的 ads.txt、共用追蹤碼、同一張憑證** — 能綁定操作者群組
2. **cloaking、偽造版本、跨域 server 模板** — 主動規避的行為觀察
3. **共用廣告帳號** — 幾乎都是大路貨，不要拿來宣稱同一操作者

---

## 跨案件記憶

```bash
kwara index build --case 1                    # 把這個案子的訊號存進索引
kwara index lookup G-B2C3D4E5F6               # 這個值以前出現在哪些案子
kwara index recurring                         # 跨多個案件再現的訊號
kwara index crosslinks                        # 第三方 endpoint 本身也是被調查的網域
```

`recurring` 的結果要**看 `domain_count`**：只涵蓋一個網域的「跨案件重複」通常是同一個網站被兩個案件各收一次，不是真的在別處又出現。

---

## 證據在哪

擷取庫用 `scan_run_id` 當目錄名，所以檔案系統本身看不出哪個目錄屬於哪個網域。

```bash
kwara evidence list --domain visitor-landing.example       # 跨案件找這個網域的證據
kwara evidence describe                       # 每個目錄放一份 capture.json 說明
kwara evidence browse --out ~/evidence-area --case 1
```

`browse` 用網域當目錄名建一棵符號連結樹，可以直接用檔案總管走進去看截圖。證據不會被複製，樹隨時可重建。

上面三個都是**從資料庫的一列出發**，問「它指的檔案還在嗎」。反方向要另一個指令：

```bash
kwara evidence reconcile                       # 磁碟上有什麼是資料庫不知道的
kwara evidence reconcile --attach              # 乾跑：哪些可以救回
kwara evidence reconcile --attach --apply      # 真的寫入
```

一列快照可能會失去它的路徑——批次逾時、重新擷取時把該列改指新目錄、兩次調查之間換過資料庫——檔案就留在磁碟上，沒有任何東西指向它。kwara 裡沒有別的功能看得見這件事。

**先看 `safe`。** 只要有任何「可能擁有這些擷取」的資料庫讀不到，它就是 false，這時所有「孤兒」判定都只是暫定的。「孤兒」是相對於**一組**資料庫講的：那組來自跨案件索引，加上你用 `--also-db` 指名的。只拿一個資料庫去判，另一個調查的證據就會長得像垃圾。

`--attach` 拒絕的比接受的多很多，而**拒絕的理由才是重點**。只有當「從**產出物**還原出的網域」是該 scan_run 曾被觀察到抵達過的，而且擷取時間晚於掃描時間，才會掛回去——scan_run 編號跨資料庫不穩定，光憑目錄編號證明不了任何事。沒通過的證據仍然是真的，只是它與現有資料庫的連結已經斷了，而工具不會替你發明一條。

`reconcile` 不刪任何東西。

---

## 交付

```bash
kwara export case --case 1
```

ZIP 含 CSV、截圖、HTML、HAR、稽核紀錄、SHA-256 manifest、中英雙語 README。設了 `KWARA_HMAC_KEY` 才有簽章；沒設的話 manifest 會**自己聲明**未簽章（`integrity_warning`），不會假裝有。

`restore_from_export.py` 可以從封包還原資料庫——收件者可以自己重建，不必信任你的轉述。

---

## 風險旗標

| 旗標 | 意義 |
|---|---|
| `multi_hop` | Redirect chain ≥ 3 跳 |
| `no_https` | 落地頁使用 HTTP |
| `new_domain` | 網域建立未滿 180 天 |
| `suspicious_download` | 落地 URL 結尾為 .exe、.apk、.zip 等 |
| `high_tracker_count` | 頁面接觸 ≥ 3 個已知追蹤服務 |
| `url_shortener_chain` | 最終 URL 仍是已知短連結服務 |
| `capture_error` | 截圖擷取失敗 |

---

## 主動發現

判別器可以從候選網域裡找出與已知目標同源的站。它是**另一條工作流**，見 [agent-interface.md](agent-interface.md) 的 `discover` 章節。

環境變數完整清單見 [README.zh-TW.md](../README.zh-TW.md)。
