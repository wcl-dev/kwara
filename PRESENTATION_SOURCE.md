# kwara 簡報來源文件（給 Claude Design 用）

> 用法：把整份檔案丟給 Claude Design，每個「Slide N」自成一張投影片。
> 每張投影片提供：標題、Key Points（投影片內容）、Visual（建議視覺呈現）、Speaker Notes（口頭講稿）。
> 全篇用 QSH 100 筆 Facebook 留言案件作貫穿範例（2026-04-28 端到端驗證）。

---

## Slide 1 — 封面

**標題**：kwara — 在地分析師的訊息戰場域調查工具

**副標**：URL → 操作者 cluster：用一台筆電做出對接得上 trust&safety 平台的證據

**Visual**：純文字封面 + 一個漏斗圖示「100 則 FB 留言 → 2 個操作者集群」

**Speaker Notes**：
- kwara 是給單機分析師用的證據級調查工具
- 不是 SaaS、不是爬蟲、不需要外部 API key
- 今天用一個真實案件（QSH Trend 監控的 100 則 FB 留言）展示工具的證據鍊
- 結論先講：100 則留言、18 個 FB 帳號、看似 4 個域名 → 工具收斂出 2 個獨立操作者集群

---

## Slide 2 — 我們在試圖回答什麼問題

**標題**：FIMI / clickbait 的核心調查問題

**Key Points**：
- 看到一則 FB 貼文 → 連到一個域名 → 然後呢？
- 三個必須回答的問題：
  1. **這個域名背後是誰？**（操作者識別）
  2. **這個操作者還做了哪些其他事？**（cluster 擴張）
  3. **怎麼把證據交出去能被採納？**（trust&safety 平台、註冊商、警方）
- 困難點：
  - 多重 sock-puppet FB 帳號分散風險
  - Cloudflare proxy 隱藏真實主機
  - 換殼域名混淆 redirect chain
  - WHOIS privacy 隱藏註冊資訊

**Visual**：四宮格圖示 — 各代表 FB 帳號、Cloudflare 雲、redirect 鏈、隱蔽 WHOIS

**Speaker Notes**：
- 這些不是新問題、業界各有工具
- 但分析師的痛點是：證據要能「對接」trust&safety 平台、要可重現、要能匯出
- kwara 的設計是把這幾個層級的訊號整合在一個工作流裡

---

## Slide 3 — 案件：QSH 100 則 FB 留言

**標題**：今天的範例案件

**Key Points**：
- 來源：Trend Micro QSH 監控（公開疑似 clickbait FB 留言）
- 100 則 Facebook 留言、橫跨 7 天（2026-03-23 → 2026-03-30）
- 18 個 distinct FB 帳號（top 4：好運旺旺來、恭喜發大財、韓流看看、按赞财运来）
- 4 個 distinct 原始域名：hubsite.example、crawlerlanding.example、crawlerlanding2.example、satellitesite.example
- **問題**：這 100 則留言背後是 1 個操作者？4 個？還是其他？

**Visual**：左邊 18 個小頭像（FB 帳號）、中間箭頭、右邊 4 個域名 logo；下方問號「?」

**Speaker Notes**：
- 從原始資料分析師能看到的就這些
- 18 個帳號分散貼到 4 個域名 — 直覺會以為操作者比較分散
- 我們即將用 6 層證據鍊收斂這個問題

---

## Slide 4 — kwara 的工作流

**標題**：三段式工作流

**Key Points**：
- **匯入（Input）** — CSV / 訊息列表 → message_evidence 與 url_artifacts 表
- **調查（Investigate）** — 對每個 URL 跑 6 層分析
- **保存（Preserve）** — 自動產出可驗證的 evidence pack（manifest.sha256 + 可選 HMAC 簽章）
- 全程 single-user、本機、SQLite；不依賴外部 API key

**Visual**：三欄式流程圖 — 左 Input、中 Investigate、右 Preserve；中間段內含「6 層」標示

**Speaker Notes**：
- 「6 層」是後面 6 張投影片要詳細展開的
- Preserve 段是 kwara 跟一般爬蟲工具最大的不同 — 證據完整性是設計第一原則
- 過 5 輪第三方 codex review、所有 evidence-integrity finding 都已修復

---

## Slide 5 — 第 1 層：URL 參數歸屬

**標題**：把廣告 / 追蹤參數翻譯成平台

**Key Points**：
- 分析師看到 `?utm_term=145` 不會立刻知道這是什麼平台的什麼角色
- kwara 的 `param_attribution` 模組對 80+ 常見 param key 做歸屬：
  - `utm_term` / `utm_source` / `gclid` → Google Analytics / Ads
  - `fbclid` → Meta
  - `_kx` → Klaviyo
  - `mc_eid` → Mailchimp
- 結果：`(param_key, value, owner_kind, platform_id, purpose)`

**QSH 命中**：

| param_key | value | platform | post_count |
|---|---|---|---|
| `utm_term` | 145 | google_analytics | **54** |
| `utm_term` | 8901 | google_analytics | 9 |
| `uid` | 638 | generic（crawlerlanding sub-campaign ID） | 9 |

→ `utm_term=145` 出現在 54 篇貼文 = 同一個 Google Ads sub-campaign 在 54 處投放

**Visual**：一張 URL 字串在中間、上下用箭頭標出「utm_term=145」這段被 highlight、旁邊浮出「Google Ads campaign #145」標籤

**Speaker Notes**：
- 重點不是「我們知道 utm_term 是什麼」（每個分析師都知道）
- 而是「跨 100 則貼文聚合 → 看到單一 campaign ID 在 54 處投放」這個尺度的觀察用肉眼會漏
- Owner-kind enum 的設計確保 dedup 用 symbol、不是顯示字串

---

## Slide 6 — 第 2 層：Redirect Chain & Wrapper 偵測

**標題**：把換殼網域抓出來

**Key Points**：
- 每個 URL 跑 redirect chain（記每一跳的 status / Location）→ 存進 `redirect_hops` 表
- `clustering_url.wrapper_relationships` 找 N→1 模式（多個原始域名→同一終點域名）

**QSH 命中**：

```
crawlerlanding.example (21 URL) ─┐
                     ├─ 2-hop redirect ─→  visitorlanding.example
crawlerlanding2.example ( 2 URL) ─┘
```

23 則貼文表面上連 crawlerlanding，**實際全部落到 visitorlanding.example**。

**參數轉換被工具看到**：
- 原始 `crawlerlanding.example/redacted139/277290?uid=638`
- redirect 後 `visitorlanding.example/redacted139/277290?utm_term=638#638`
- → operator 後端 PHP 把 `uid=` 改名 `utm_term=`，這個改寫規則本身是強指紋

**Visual**：兩條彎曲箭頭從 crawlerlanding.example、crawlerlanding2.example 收斂到 visitorlanding.example、上方標 `?uid=` → `?utm_term=`

**Speaker Notes**：
- 真正的落地網域只有 3 個（visitorlanding/hubsite/satellitesite）不是表面的 4 個
- 換殼網域是耗材式設計 — 一個被檢舉就換 crawlerlanding.com / .io / .xyz；分析師需要看穿這層
- 這個 view 在 kwara 的 `tab_analyze` → `_sub_network`

---

## Slide 7 — 第 3 層：TLS 憑證 & ASN 共用

**標題**：基礎設施聚合

**Key Points**：
- 每個 final URL 拉 TLS 憑證、做 IP / ASN lookup
- 兩個分析向度：
  1. **`shared_certificates(by_issuance)`** — 多個域名在**同 CA、相近時間**獲簽 → 批次部署訊號
  2. **`asn_clusters`** — 多個域名在同一 ASN/ AS_org → CDN/主機商共用

**QSH 命中**：

```
ASN 共用：3 個終點域名全部在 AS13335 CLOUDFLARENET (US)
  visitorlanding.example     172.67.183.203
  hubsite.example    172.67.207.101
  satellitesite.example  172.67.164.51
```

```
CA 共用：3 個域名所有憑證全部由 Google Trust Services (WE1) 簽發
時間窗命中：
  satellitesite.example 與 visitorlanding.example 的憑證在 4h50m 內陸續簽發
  (Mar 30 23:00:57 → Mar 31 03:50:21 GMT)
```

**Visual**：左邊一張 Cloudflare 雲 logo 包住 3 個域名、右邊時鐘圖示「5 小時內連續簽發 2 張憑證」

**Speaker Notes**：
- ASN 全部是 Cloudflare 看似無資訊量、但「100% 一致」反而是訊號
- 真正有判別力的是 cert by_issuance window — 5 小時內同 CA 連續簽兩張、不是巧合
- 這層的限制：當 operator 全用 Cloudflare proxy + Let's Encrypt / GTS，cert 訊號退化；要靠下一層的 HTML pixel

---

## Slide 8 — 第 4 層：HTML 內嵌 Pixel/GA/GTM 抽取（最關鍵）

**標題**：從操作者**自己埋的追蹤碼**識別操作者

**Key Points**：
- Playwright 抓真實 HTML → `fingerprints.py` 抽取：
  - Google Analytics 4（`G-XXXXXXXXX`）
  - Google Tag Manager（`GTM-XXXXXXX`）
  - Meta Pixel（`fbq('init', 'NNNNN')`）
  - Google Ads conversion ID
  - TikTok / Microsoft Clarity / Hotjar / LINE Tag / X Pixel（Phase 3 第二批）
- **必須有 invocation context**（不抓 commented-out / placeholder）：
  - vendor URL host（`googletagmanager.com`、`google-analytics.com`、`clarity.ms`）
  - 函式呼叫（`gtag(`、`fbq(`、`twq(`）
  - `dataLayer` 字面量

**QSH 命中（最關鍵）**：

| 域名 | GA4 | GTM |
|---|---|---|
| **hubsite.example** | `G-T5N9K2Q7W3` ×73 | — |
| **satellitesite.example** | `G-T5N9K2Q7W3` ×4 | — |
| visitorlanding.example | `REDACTEDID60` ×23 + `REDACTEDID79` ×23 | `GTM-T5N9K2Q` ×23 |

→ **hubsite + satellitesite 共用 `G-T5N9K2Q7W3`** = 同一個 Google Analytics 帳號 = **同一操作者**
→ visitorlanding 自己的 GA4 + GTM = **另一個獨立操作者**

**Visual**：左半邊一個橢圓圈住 hubsite + satellitesite、標記 `G-T5N9K2Q7W3`；右半邊另一個橢圓圈住 visitorlanding、標記 3 個自己的 ID

**Speaker Notes**：
- Google Analytics 帳號是 operator 註冊時用真實 Google 帳號開的、無法 Cloudflare proxy 隱藏
- 兩個域名共用同一個 GA4 帳號 = 操作者沒辦法解釋的鐵證
- 這是 kwara 證據力最強的單一層
- Phase 2 開發重點：抽取必須有 invocation context、否則會把 placeholder（`UA-XXXXXXX`）誤抓進來

---

## Slide 9 — 第 5 層：HAR 第三方端點聚合

**標題**：廣告供應鏈共用偵測

**Key Points**：
- Playwright 同步抓 HAR（網路請求記錄）
- 從每筆 capture 抽出非自身域名的請求 endpoint
- 篩掉 vendor noise（Cloudflare insight、Google Tag Manager 自家、FB connect）
- 跨域名共用的 endpoint = 廣告供應鏈共用訊號

**QSH 命中**：

9 個第三方端點橫跨 ≥ 2 個目標域名：

| Endpoint | 跨域 | 性質 |
|---|---|---|
| adreq.adster.tech | visitorlanding + hubsite | DSP 競價 |
| dsp.adkernel.com | visitorlanding + hubsite | DSP |
| match.prod.bidr.io | satellitesite + hubsite | DSP |
| sync.ipredictive.com | satellitesite + visitorlanding | 行為再標的 |
| um.simpli.fi | visitorlanding + hubsite | DSP |
| statics.privatecdn.example | satellitesite + hubsite | CDN |

**Visual**：3 個域名（hubsite / visitorlanding / satellitesite）在邊緣、9 個 endpoint 在中間、用線連起來；明顯密集

**Speaker Notes**：
- 即使 GA4 不共用（如 visitorlanding vs cluster A），廣告供應鏈仍橫跨
- 兩種解讀：
  1. 獨立操作者選用了相似的供應鏈組合（巧合，但 9 個全中已超出巧合範圍）
  2. 同一個行銷代理在背後委外操作 ≥ 2 個 cluster
- 是「補強第 4 層」的訊號、不會單獨拿來定操作者

---

## Slide 10 — 第 6 層：URL Param × 帳號 矩陣

**標題**：誰在投哪個 sub-campaign

**Key Points**：
- 把第 1 層的 (param_key, value) × 第 4-5 層的 final domain × 帳號 三維交叉
- 看「同一個 sub-campaign 被哪些帳號投放」、「同一個帳號投了哪些 sub-campaign」

**QSH 命中**：

| 終點域名 | 跨 actor 數 |
|---|---|
| hubsite.example | 9 個 FB actor |
| **visitorlanding.example** | **13 個 FB actor**（番茄小說、養生頭條、Senior Chef、故事分享、有故事的人、女人帮、天天看戲、言情小說家、言情迷……） |
| satellitesite.example | 3 個 FB actor |

→ visitorlanding.example 的 13 個不同 FB 帳號全部用 crawlerlanding 換殼指向同一終點 = 經典 sock-puppet → 單一基礎設施

**Visual**：一張表 — 13 個 FB 帳號頭像在左、單一 visitorlanding logo 在右、中間 23 條收斂線

**Speaker Notes**：
- 這層直接回答 slide 3 的問題：18 個帳號分散貼到 4 個域名 → 收斂後變成 13 個帳號全部往 visitorlanding cluster
- account_content_matrix 設計上**不自動下協同行為判定**（避免過擬合）；只把矩陣攤給分析師看

---

## Slide 11 — 結論：兩個操作者集群

**標題**：100 則留言 → 2 個獨立操作者

**Key Points**：

**集群 A（hubsite + satellitesite）**
- 共用 GA4 `G-T5N9K2Q7W3`
- 9 個 FB actor 投 hubsite、3 個投 satellitesite
- WAF 啟用（擋非瀏覽器 UA）

**集群 B（visitorlanding.example，含 crawlerlanding 換殼前端）**
- 自己的 2 個 GA4 + 1 個 GTM
- 13 個 FB actor 透過 crawlerlanding 換殼投放
- WAF 不啟用

**集群間共同點**：
- 全 Cloudflare ASN
- 全 Google Trust Services 簽憑證
- 9 個共用 DSP / sync endpoint
- → 可能委外同一行銷代理；單獨不能斷定同操作者

**Visual**：兩個明顯分隔的橢圓 — 左邊 A（hubsite + satellitesite + 9+3 帳號）、右邊 B（visitorlanding + crawlerlanding + 13 帳號）；中間虛線連到「9 個共用 DSP」灰色框

**Speaker Notes**：
- 這個收斂結果不是工具自動下的判定 — 是工具把 6 層訊號攤開、分析師看了之後得出
- 證據鍊互相獨立指向同一切割線 = 強推
- 對外溝通時可以指認哪一層是哪個證據

---

## Slide 12 — 額外發現：OPSEC 落差

**標題**：兩條 fetch 路徑的對比是 OPSEC 探針

**Key Points**：
- kwara 對每個 URL 跑兩條路徑：
  - **輕量 HTTP fetch**（UA = `KwaraScanner`，純 `requests.get`）— 容易被 WAF 認出
  - **Playwright**（真 Chromium、真 fingerprint）— 跟一般使用者一樣
- 把兩者結果擺在一起 → OPSEC 程度

**QSH 命中**：

| 域名 | lightweight 成功 | Playwright 成功 | OPSEC 等級 |
|---|---|---|---|
| visitorlanding.example | 23/23 (100%) | 23/23 (100%) | **弱**（不擋 UA） |
| hubsite.example | 12/73 (16%) | 73/73 (100%) | **中**（擋 UA、放 Chromium） |
| satellitesite.example | 0/4 (0%) | 4/4 (100%) | **強**（嚴格擋 UA） |

→ hubsite + satellitesite 都擋、visitorlanding 都放 = **獨立於 GA4 訊號**指向同樣的兩個操作者切割

**Visual**：水平柱狀圖 — 三個域名各兩根柱（lightweight vs Playwright），明顯左側兩個域名 lightweight 柱很矮、Playwright 柱很高

**Speaker Notes**：
- 這是兩個獨立訊號各自指向同一切割線的另一個例子
- 同時也驗證 Phase 3 輕量 fetch 路徑的 trade-off — 對有 OPSEC 的站、Playwright 仍是不可取代的

---

## Slide 13 — 工具盲點：Conditional Cloaking

**標題**：誠實面對工具沒看到的東西

**Key Points**：
- crawlerlanding.example 的真實行為：

| URL | 結果 | 內容 |
|---|---|---|
| `crawlerlanding.example/redacted139/277290`（無 uid） | HTTP 200, 25 KB | 真正的文章內容 |
| `crawlerlanding.example/redacted139/277290?uid=638`（有 uid） | HTTP 302, 0 B | → visitorlanding.example |
| `crawlerlanding.example/`（根） | HTTP 200, 45 KB | 「世語圖說」首頁 |

→ crawlerlanding 是 **conditional cloaker**：
1. 對 FB 點擊用戶（帶 uid）：302 推到 visitorlanding 變現
2. 對 SEO 爬蟲（無 uid）：吐真內容、被 Google 收進索引
3. 對人工調查者「先清掉 tracking param」的直覺：**反而被騙**

**kwara 今天**：一律帶 tracking param 掃 → 永遠看不到 crawlerlanding 服務 SEO 爬蟲那一面 → 誤判為 pure wrapper

**改善已列入 Phase 4**：cloaking detection（半天工程量）

**Visual**：crawlerlanding 域名圖示分裂成三條線 — 一條到 visitorlanding（標 FB 用戶）、一條到 Google 索引（標 SEO 爬蟲）、一條到分析師被打問號

**Speaker Notes**：
- 這是這次 100 筆 E2E 跑出來才發現的盲點
- 工具的價值在「找到並承認盲點」這個過程本身
- 公開承認盲點 + 提出工程改善 = 證據級調查工具的基本誠實

---

## Slide 14 — OPSEC 漏洞：Response Headers

**標題**：手動 curl 撈到工具沒看的東西

**Key Points**：
- 在這次盲點排查中、用 `curl -D` 撈 crawlerlanding 302 response，發現 3 個 OPSEC 漏洞：

```
HTTP/2 302
x-server-hosted: Malaysia Cloud Pte Ltd      ← 真實主機商外洩
x-powered-by: Apache/2.5.1 (Win64) PHP/8     ← 假版本（Apache 2.5.1 不存在）
location: ...?utm_term=638#638               ← 後端參數改寫規則
```

→ Cloudflare proxy 後面的真實 origin（Malaysia Cloud Pte Ltd）**直接被 origin 自己的 header 透出來**
→ Apache 2.5.1、OpenSSL 1.1.2e 都是不存在版本 = 故意造假指紋（operator 主動規避偵測）

**kwara 今天**：`redirect_hops` 只存 `(status_code, location)`，其他 30+ header 全部丟掉

**改善已列入 Phase 4**：response header 保留（1.5 天工程量）解鎖 4 類分析

**Visual**：一張 HTTP response screenshot、3 行被框紅；旁邊文字「kwara 今天看到 0 / 3」

**Speaker Notes**：
- 對外 abuse 申訴時、`x-server-hosted: Malaysia Cloud Pte Ltd` 直接給新加坡警方 / Malaysia Cloud 就行 — 繞過 Cloudflare takedown 阻力
- 多域名共用相同假 `x-powered-by` 模板會是「同 server 設定」的強指紋（同操作者證據力 ≈ GA4 共用）
- 同樣是「我們找到了、我們承認、我們安排修」

---

## Slide 15 — 證據完整性

**標題**：能交出去的證據鍊

**Key Points**：
- 每筆 capture 走 per-capture 子目錄：`data/snapshots/{scan_run_id}/{timestamp}_{rand4}/`
- Manual upload / lightweight fetch / Playwright 三條路徑全部走同一個目錄結構
- Export ZIP：
  - 內含 manifest.json（每個 artifact 的 sha256 + size + capture method）
  - 旁附 manifest.sha256（manifest 本身的 hash）
  - 可選 HMAC-SHA256 簽章（`KWARA_HMAC_KEY` 環境變數）
- Restore：從 ZIP 還原 DB + snapshot 檔案，driven 自 manifest

**過 5 輪第三方 codex review、所有 evidence-integrity finding 已修復**

**Visual**：一個信封圖示打開，露出 manifest.json + manifest.sha256；旁邊 5 個綠色勾代表 5 輪 review

**Speaker Notes**：
- 證據完整性是設計第一原則 — 不是事後加的
- 5 輪 codex（外部 LLM 第三方審查）找出 15 個 finding，全部已修復
- 這套設計可以對接 trust&safety 平台（Meta、Google）和註冊商的 abuse 流程

---

## Slide 16 — Roadmap：下一步

**標題**：12 個月開發路徑

**Key Points**：

**立即（本月）**
- Cloaking detection — 補上 conditional cloaker 偵測
- Response header 保留 — 解鎖 origin host / 假版本 / cookie origin leak / cross-domain template diff 4 類分析

**短期（1-2 週）**
- OPSEC profile view — lightweight vs Playwright 對比視覺化
- 跨案件查詢 — 「`G-T5N9K2Q7W3` 出現在過去哪些案件」（kwara 的 single-user 縱向追蹤優勢）

**中期（1 個月）**
- PDF executive summary（中英）
- abuse 表單 pre-fill（Cloudflare / GTS / Meta / 各註冊商）
- urlscan / Wayback 自動提交

**Backlog**（待驗證命中率）
- 威脅情資 feed 整合
- 網路圖視覺化
- 定期 re-check / 變化偵測
- CMS 指紋

**Visual**：時間軸（4 個刻度：本月 / 1-2 週 / 1 個月 / Backlog），各刻度下面列工作項目

**Speaker Notes**：
- 詳細的 ROADMAP.md 在 repo 根目錄
- 每項都有對應的工程模組與預估時間
- 不會做的列表也明確：多人 SaaS、AI 自動下協同判定、廣面爬蟲

---

## Slide 17 — 設計理念

**標題**：工具的設計選擇

**Key Points**：

| 是 | 不是 |
|---|---|
| Single-user local SQLite | SaaS / 多人協作 |
| Evidence-grade | 廣面 scraper |
| 工具攤訊號、分析師判讀 | AI 自動下協同行為判定 |
| 可重現、可驗證、可匯出 | 黑盒推論 |
| 對接 trust&safety 流程 | 內部觀察用 |
| 開源 / 本地執行 | 雲端依賴 |

**Visual**：對照表（左邊綠勾、右邊紅叉）

**Speaker Notes**：
- 這些選擇是 trade-off、不是優越論
- single-user 換來的是分析師主權 + 隱私 + 速度
- 不自動下判定換來的是「不會過擬合」與分析師可解釋性
- 證據級換來的是對接 trust&safety / 法務的可能性

---

## Slide 18 — 結語

**標題**：kwara 能做什麼、不能做什麼

**Key Points**：
- **能做**：
  - 把分散的 URL → 收斂出操作者 cluster
  - 用 6 層獨立訊號互相驗證（不依賴單點）
  - 產出可對外溝通的 evidence pack
  - 在單機上 30 分鐘跑完 100 筆案件
- **不能做（也不打算做）**：
  - 跨組織協作 / 共享案件 DB
  - 自動下「這就是 FIMI」的判定
  - 即時監控 / 主動爬蟲

**Visual**：兩欄對照、左欄綠色「能」、右欄灰色「不能」

**Speaker Notes**：
- 工具不是萬能、會有盲點（cloaking 就是一例）
- 我們承認盲點 + 安排修補 + 對外公開驗證
- 這就是 evidence-grade 工具該有的樣子

---

## Slide 19 — Q&A / 聯絡資訊

**標題**：Questions & Discussion

**Key Points**：
- 工具：開源、本地執行（Python + SQLite + Playwright）
- 文件：
  - `ROADMAP.md` — 開發路徑
  - `QSH_E2E_TEST_REPORT_2026-04-28.md` — 本次完整驗證報告
- 聯絡：（填入聯絡資訊）

**Visual**：純文字、簡潔

**Speaker Notes**：
- 留 5-10 分鐘提問
- 常見問題預先準備：
  - 跟 Maltego / urlscan / OpenCTI 的差異？
  - 為什麼用 SQLite 不用 graph DB？
  - 法律 / 隱私顧慮？
  - 開源授權？

---

# 附錄：可能被問到的常見問題

## Q1：跟 Maltego / urlscan / OpenCTI 的差異？

- Maltego：圖形化關聯工具、強在視覺化、弱在 evidence pack
- urlscan：公開服務、強在第三方背書、弱在分析師主權（資料上傳）
- OpenCTI：威脅情資平台、適合 SOC、對 FIMI 命中率未驗證
- kwara：定位在「分析師主權 + 證據級匯出」、針對 FIMI / clickbait 在地優化

## Q2：為什麼是 SQLite 不是 graph DB？

- SQLite：單機、無依賴、易備份、易還原
- graph DB：要伺服器、運維成本高、對單機分析師不划算
- 跨案件查詢的 graph-like 需求用集中索引 DB 解決（Phase 5.1）

## Q3：法律 / 隱私顧慮？

- kwara 只跑分析師明確匯入的 URL、不主動爬網
- 不收集個人資料；只收集網站基礎設施訊號（cert/ASN/pixel）
- 案件 DB 在本機、分析師完全控制
- 對外 evidence pack 僅在分析師主動匯出時產生

## Q4：開源授權？

（依實際選擇填入）

## Q5：跟 OSINT 的工作分工？

- kwara 不做人物 OSINT、不做財務追蹤
- 專注「網路基礎設施 → 操作者 cluster」這一層
- OSINT 工具的輸出（人物、地址、財務）可進入 kwara 的 case 描述供分析師交叉

---

# 給 Claude Design 的格式建議

- 整體調性：工程實證、不誇張、不畫超出能力的大餅
- 每張投影片用一個明確 anchor case（QSH 100 筆）— 避免抽象
- 圖示風格：簡單 line icon，不要 stock photo
- 字體：英文 sans-serif、中文思源黑體 / 蘋方
- 配色：節制的兩色（深藍 + 灰）+ 少量綠色強調已驗證 / 紅色強調盲點
- 每張投影片的視覺重點：「比較對照」「收斂」「分層」這三種模式
- 切勿把 6 層全部放一張投影片 — 一層一張
- 切勿用 emoji（工具本身已從 UI 中移除 emoji，簡報應一致）
