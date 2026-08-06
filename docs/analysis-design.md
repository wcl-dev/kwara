# kwara 分析層 — 原理與設計

> 對象：開發者、研究員、想評估 kwara 演算法或接手開發的技術人員
> 目的：說明 kwara 各個分析模組**怎麼運作**、為什麼這樣切
> 涵蓋範圍：分析層（唯讀聚合）。蒐集端（scan / network / domain / page /
> corroboration）不在此文範圍，見 [README](../README.zh-TW.md)。

整個分析層由三大唯讀聚合模組構成，共同使用 [param_attribution.py](../kwara/param_attribution.py) 的 platform 常數做去重 key：

| 模組 | 訊號層 | 函式 |
|---|---|---|
| [clustering_url.py](../kwara/clustering_url.py) | URL / 貼文層 | `shared_destinations`、`wrapper_relationships`、`shared_params`、`shared_param_keys` |
| [clustering_infra.py](../kwara/clustering_infra.py) | 基礎設施層 | `asn_clusters`、`shared_certificates`、`certificate_authorities`、`shared_tracking_ids`、`ad_tracking_platforms`、`shared_endpoints`、`shared_ad_accounts` |
| [header_analysis.py](../kwara/header_analysis.py) | HTTP 鑑識層 | `per_domain_constants`、`cross_domain_shared_template`、`detect_fake_versions`、`cookie_origin_signals` |

外加兩個獨立的訊號模組：[cloaking.py](../kwara/cloaking.py)（主動防偵測對抗）、[opsec.py](../kwara/opsec.py)（路徑差異 OPSEC profile）；以及一個蒐集端模組 [adstxt.py](../kwara/adstxt.py)，負責抓取與解析 `ads.txt`，供 `shared_ad_accounts` 聚合（見 §十一）。

所有聚合函式都是**唯讀 SQL + Python 字典聚合**，沒有外部呼叫、沒有 i18n，可以隨時重跑。

> **介面對應**：這些函式同時供 Streamlit UI 與無介面 CLI／MCP 呼叫——兩條路徑走同一份程式碼，不會各自漂移。CLI 指令與 MCP 工具清單見 [agent-interface.md](agent-interface.md)。

---

## 一、訊號分層

從匿名化抗性由低到高排列，這也是 kwara 蒐證鏈往上爬的順序：

| 層級 | 訊號 | 抗匿名化能力 | 關鍵函式 |
|---|---|---|---|
| 網路層 | redirect topology | 低 | `scanner.scan_url()` |
| 主機層 | IP、ASN、託管商 | 低（Cloudflare 全包） | `asn_clusters()` |
| 網域層 | WHOIS、註冊商 | 低（GDPR 遮蔽） | `whois_lookup.py` |
| 憑證層 | TLS issuer、serial、SAN、簽發時間 | 中 | `shared_certificates()`、`certificate_authorities()` |
| URL 參數層 | utm_*、fbclid、aff_id、uid | 中 | `shared_params()`、`shared_param_keys()` |
| Wrapper 關係層 | 跨域 redirect 結構與參數改名 | 中 | `wrapper_relationships()` |
| HAR endpoint 層 | 第三方 hostnames 跨域共用 | 中-高 | `shared_endpoints()` |
| HTML 嵌入層 | Pixel ID、GA、GTM、AdSense、FB Page | 高（綁營收帳號） | `shared_tracking_ids()`、`fingerprints` |
| **HTTP header 鑑識層** | server template、版本造假、origin leak | 高（origin header 不被 CDN 擦除） | `header_analysis.py` 4 函式 |
| **Cloaking 訊號層** | with-param vs without-param 行為差異 | **最高**（主動規避意圖） | `cloaking.detect_cloaking()` |
| **OPSEC 路徑層** | lightweight vs Playwright 成功率 | 中-高（WAF 部署模板） | `opsec.compute_opsec_profile()` |
| **變現帳號層** | `ads.txt` DIRECT 帳號、逐字節相同模板 | 高（綁收款對象） | `shared_ad_accounts()` |

各層獨立蒐集、獨立可驗證，最後在 `ad_tracking_platforms()` 把同一 platform 的 URL 參數與 HTML pixel 合併，標出獨立確認（cross-source confirmation）。

---

## 二、URL 參數層 — 兩種「重複」的差異

這是常被混為一談、但其實刻意切成兩個函式的設計。

### `shared_params(key, value)` — 同一活動

兩個貼文帶到 `?utm_term=145` 同樣的值——這是**同一支 campaign**。

實作要點：
- 同時看 `original_url`（短連結）與 `final_url`（落地頁），因為 wrapper redirect 會改 key 名稱（已驗證 `crawlerlanding.example/?uid=` → `visitorlanding.example/?utm_term=`）。
- 過長的 value（base64 token、JWT、affiliate 加密 ID）改用 SHA-256 prefix 比對——同一支不透明 token 仍能聚合，但表格顯示 hash 而非原值（`_normalize_param_value`，門檻在 [config.py](../kwara/config.py)）。
- 至少跨 2 篇貼文才入列；單篇出現的不算 cluster。

### `shared_param_keys(key, *)` — 同一後台

操作者給每位受害者派一支獨一無二的 `?aff_id=A1`、`A2`、`A3`……每個 value 都只出現一次，`shared_params()` 看不到任何聚合。但**這個 key 本身的存在**就是證據——它指向同一個操作者的後台。

判斷規則（門檻全部在 `config.py`）：
- `PARAM_KEY_MIN_POSTS`：至少要在這麼多篇貼文裡出現。
- `PARAM_KEY_MIN_VALUES`：要有這麼多種不同的 value（過濾掉「全部都是同一支 campaign」的雜訊）。
- `PARAM_KEY_MAX_DOMAINS`：domain 數不能太多（過濾 `?q=` 這種四處可見的通用 key）。

三個門檻同時成立才入列。

兩個函式的關係：`shared_params` 抓「同活動」、`shared_param_keys` 抓「同後台」——前者是同一筆內容散播，後者是同一個系統發內容。互補而非冗餘。

---

## 三、Wrapper 關係層 — 跨域 redirect 結構

`wrapper_relationships()` 把 `(original_domain → final_domain)` 落到不同網域的 redirect 對自動聚合出來。crawlerlanding → visitorlanding 是教科書範例：分析師收到 `crawlerlanding.example/redacted139/X?uid=…`，但 scan 解完後全部落到 `visitorlanding.example`，且 `uid` 在跳轉中被改名為 `utm_term`。

每個 wrapper 對都帶：
- `url_count` / `post_count`
- `min_hops` / `max_hops`（有些 wrapper 走 1 跳、有些 2 跳）
- `sample_urls`（前 5 個 distinct original_url）

沒有這個函式，分析師要手動把每個 `url_artifacts.original_url` 對 `scan_runs.final_url` 一個個比對。

---

## 四、憑證層 — 兩種 cluster 的分水嶺

`shared_certificates()` 同時輸出兩類 cluster：

### `by_cert` — 同一張憑證

由 `(issuer, serialNumber)` 當 key，同一張 cert 蓋到 ≥ 2 個落地網域才入列。憑證序號全球唯一——這是**同一台伺服器或同一操作者**的鐵證。SAN 名單也帶上來，方便下一步擴搜。

### `by_issuance` — 24 小時窗口內批次簽發

不同 cert，但 `notBefore` 在 24 小時內。實作上先把全部 cert 依 `notBefore` 排序，貪婪地把間隔不超過 24 小時的併成一群——**同一群 cert 涵蓋 ≥ 2 個落地網域才入列**（避免「同一網域連續換證」誤判）。

OPSEC 解讀：操作者很可能用同一個自動化部署 pipeline 同步上線多個域，但每域一張獨立 cert——`by_cert` 抓不到、`by_issuance` 抓得到。QSH 100 筆驗證裡 visitorlanding.example 與 satellitesite.example 在 5 小時內由 Google Trust Services WE1 連簽 4 張，正是這個訊號。

`certificate_authorities()` 是補充視角：列出哪些 CA 涉案、各自蓋多少網域——做 accountability mapping 用，不是 cluster。

---

## 五、HTML 嵌入層 — 為什麼這是最強訊號之一

### 抽取（`fingerprints.extract_tracking_ids`）

不啟動 JS engine、不解 DOM——直接 regex。原理：所有主流追蹤 SDK 的 init 片段都把 ID 寫成字串字面值（`fbq('init', '…')`、`gtag('config', 'G-…')`、`ttq.load('…')`）。只要 regex **錨定 invocation context**，就能可靠地撈出來。

目前 11 個平台分三批落地：

| 批次 | 平台 |
|---|---|
| 第一批 | Meta Pixel、GA4、UA、GTM、Google Ads、TikTok Pixel |
| 第二批 | Microsoft Clarity、Hotjar、LINE Tag、X / Twitter Pixel |
| 第三批 | Google AdSense、Meta Facebook Page |

兩個重要的設計修補（codex review 之後）：

**修補 1：context-anchoring**
早期版本撈 bare token（`G-ABCD1234`）——但這字串會出現在 vendor 文件、JSON blob 註解、blog post 範例。現在每條 pattern 都要求 ID 出現在真實 invocation 裡（`gtag/ga/fbq/ttq/_lt/twq/clarity` 等函式呼叫、或 vendor host 的 URL `googletagmanager.com` / `google-analytics.com` / `clarity.ms` / `line-scdn.net`、或 GTM `dataLayer` 字面量）。

**修補 2：placeholder filter**
`G-XXXXXXXX`、`GTM-EXAMPLE` 這類佔位字串通過 regex 但不該入庫。Heuristic：split by `-`，後段任一節是「3 個以上字母全部相同」（`XXXX`/`ZZZZ`）或匹配已知 placeholder tail（`EXAMPLE`/`PLACEHOLDER`/`YOURID`/...）就剔除。注意：repeated-digit 不剔——`AW-1111111111` 在野外真的存在過，寧可保留稀有 false positive 也不要靜悄悄丟掉合法 attribution。

### 聚合（`shared_tracking_ids`）

同一 `(platform, ID)` 跨 ≥ 2 個落地網域才入列。

關鍵 SQL 設計：取 snapshot 時不取「最新一張」，而取**最新的一張可用 snapshot**（`capture_status = 'ok'` AND `tracking_ids_json` 非空）。否則一次 Cloudflare challenge 或 timeout 失敗的重新截圖，會無聲地蓋掉先前抓到的好證據。**這是必須保留的契約**——適用於 `shared_tracking_ids`、`ad_tracking_platforms`、`shared_endpoints` 三個函式。

為什麼這層訊號最強之一：
1. Pixel ID / GA property 綁定到 Meta / Google 的廣告或分析帳號，**換帳號的 OPSEC 成本 ＞ 換網域**。
2. ID 寫死在 HTML 字面值裡，Cloudflare/CDN 回傳什麼是什麼。
3. 移除 ID 等於放棄轉換追蹤——這是操作者賺錢的眼睛。

---

## 六、HAR endpoint 聚合 — `shared_endpoints`

對每個落地頁的 snapshot 讀 `request_domains_json`（Playwright 截圖時順便記錄），找出**被 ≥ 2 個落地網域呼叫的非白名單第三方 endpoint**——這往往是操作者的後台 API 或自架統計伺服器。

兩個設計重點：

- **白名單過濾**——`config.HAR_NOISE_HOSTS` 列了 fonts.googleapis.com、cdn.jsdelivr.net、jquery、googletagmanager、connect.facebook.net 等通用 CDN/SDK；不過濾的話雜訊會淹沒訊號。
- **直連 IP 標記**——`is_direct_ip` 把走 IP 而非 hostname 的請求浮到清單頂部。詐騙頁繞過 CDN 直接打 origin 後端的鐵證。

注意：lightweight HTTP fetch 路徑不會貢獻 HAR——只有 Playwright 截圖會記錄 request hostnames。

---

## 七、跨來源合併 — `ad_tracking_platforms` 的 signal_source

這個函式回答：「這個 case 涉及哪些廣告/分析平台、來源是什麼？」

對每個 platform_id，同時看：
- **URL 參數證據**：`identify_param()` 把 utm_* 對到 GA、fbclid 對到 Meta、gclid 對到 Google Ads ……
- **HTML pixel 證據**：snapshot 裡抽到的同 platform tracking ID（用 `_HTML_PLATFORM_TO_PLATFORM_ID` 把 fingerprints label 對齊到 platform_id）。

`signal_source` 四種狀態：

| 標籤 | 條件 | 解讀 |
|---|---|---|
| `both` | URL 證據與 HTML 證據**在同一個 ua_id 或 domain 上都出現** | 獨立確認——強 |
| `mixed_nonoverlap` | 兩種證據在這個 case 都有，但**從未在同一筆出現** | 仍值得列、但弱於 `both` |
| `html_embedded` | 只有 HTML pixel 證據 | 落地頁有部署但 URL 不帶參數 |
| `url_param` | 只有 URL 參數證據 | 落地頁可能阻擋了截圖、或 SDK 動態載入 |

`mixed_nonoverlap` 是 codex review 後新增的標籤——以前會被誤標成 `both`，把「兩種訊號都有」與「兩種訊號交叉確認」當成同義。實際上前者證據力低很多，UI 不該說謊。**`both` 必須要求同 ua_id 或 domain 上的 URL+HTML 交集，這是必須保留的契約。**

`classify_owner()` 同步輸出 `owner_kind`（`platform`/`generic`/`unknown`），讓 view 層用 i18n 翻譯，永遠不要把翻譯字串當聚合 key。

---

## 八、HTTP Header 鑑識層（Phase 4.2）

`scanner.py` 把每個 redirect hop 的完整 response headers 存進 `redirect_hops.response_headers_json`；`header_analysis.py` 提供四個正交的分析視角：

### `per_domain_constants` — origin host 揭露

某網域的多次掃描裡，**永遠出現**且值穩定的 header（排除 `date`、`age`、`set-cookie`、`cf-ray`、`x-amz-cf-id` 等天然會變的）。QSH 命中：crawlerlanding.example 持續吐 `x-server-hosted: Malaysia Cloud Pte Ltd`——揭露 Cloudflare 後面的真實 origin。

### `cross_domain_shared_template` — 同操作者 server 模板

多個落地網域**同時帶相同的 header 值**（特別是異常的、非預設的）。例如三個域都吐相同的假 `x-powered-by` ⇒ 同一個 server 部署模板 ⇒ **同操作者證據力比肩 GA4 共用**。重點：origin response header 不會被 Cloudflare proxy 擦掉，這個訊號繞過 CDN 隱身。

### `detect_fake_versions` — 主動造假指紋

掃 `Server`、`X-Powered-By`、`X-AspNet-Version` 等 header 的版本字串，比對已知的「不存在版本」表（Apache 2.5.1、OpenSSL 1.1.2e、PHP 9.x ……）。命中即代表 operator **故意**寫了個不存在的版本——主動防偵測訊號。

### `cookie_origin_signals` — Set-Cookie domain 洩漏

`Set-Cookie: ...; Domain=.realorigin.example` 也常洩 origin。`Path` / `Secure` / `HttpOnly` flag 的設置一致性也是指紋——同操作者的 server 設定模板會跨域帶到。

---

## 九、Cloaking 訊號層（Phase 4.1）

`cloaking.detect_cloaking(url)` 對每個帶 tracking param 的 URL 同時抓兩個版本（with-params vs stripped），比對：

| 比對欄位 | 差異閾值 | 訊號 |
|---|---|---|
| `status_code` | 不同 | cloaking suspect |
| `final_domain` | 不同 | conditional redirect |
| body sha256 | 不同 | 內容差異化（SEO/user 區別） |
| body size | > 30% 差異 | 同上 |

verdict 落到 `scan_runs.cloaking_signal_json`，四種值：`no_tracking_params`、`fetch_error`、`no_cloaking`、`cloaking_suspect`。stripped 版本的 body 也持久化為 `cloaking_alt` snapshot（`CAPTURE_METHOD_CLOAKING_ALT`）——之後可以做 SEO-side 內容分析或回頭驗。

**為什麼這是最強訊號之一**：cloaking 是 operator 寫了 PHP/middleware 邏輯**故意**對不同訪客回不同內容——這是有意識規避，不像 GA4 共用是無意識指紋。一個域被標 cloaking_suspect，已足以下「operator is intentionally evading investigation」的判定。

---

## 十、OPSEC 路徑層（Phase 4.3）

`opsec.compute_opsec_profile(case_id)` 對每個落地網域比較兩條截圖路徑的成功率：

```
              lightweight     playwright    OPSEC level
visitorlanding.example    23/23 (100%)   23/23 (100%)   low (no gate)
hubsite.example   12/73 ( 16%)   73/73 (100%)   strong (UA gate)
satellitesite.example  0/4 (  0%)     4/4 (100%)    strong (UA gate)
```

OPSEC level 規則（刻意粗略，分析師最終判讀）：

| level | 條件 |
|---|---|
| `low` | 兩條路徑成功率都 ≥ 70% |
| `medium` | playwright ≥ 70%、lightweight 在 20–70% 之間 |
| `strong` | playwright ≥ 70%、lightweight < 20% |
| `indeterminate` | 任一條無資料、或 playwright 本身失敗 |

讀的是既有的 `snapshots.capture_method` + `capture_status`，**沒新 schema**。

**判不出來是常態，不是例外。** 兩條路徑由**不同指令**填：`run attribute` 跑輕量擷取、`run snapshot` 驅動 Playwright。只跑其中一個的案件永遠產不出 level。2026-08-06 實測：六個案件裡有五個的每一個網域都是 `indeterminate`，純粹因為少跑一條路徑，而當時沒有任何地方說明原因。

所以每一列都帶 `indeterminate_reason`（`no_playwright` / `no_lightweight` / `no_capture` / `playwright_unreliable`），`insights` 的 gaps 也會報出缺哪一條。**沉默的 indeterminate 會被讀成「查過了沒發現」，但真相是「另一半根本沒蒐集」**——兩者的意思完全相反。

訊號意義：「擋 UA 但放 Chromium」是 WAF 的特定部署模板。同 case 裡多個域共享同一 OPSEC level，**獨立於 GA4 / TLS / 參數訊號**指向同操作者切割。QSH 100 筆裡 hubsite + satellitesite 兩條都擋、visitorlanding 兩條都放——獨立佐證 GA4 已揭露的兩個操作者線。

---

## 十一、變現帳號層 — `ads.txt` 與頻率加權

`shared_ad_accounts()` 讀 [adstxt.py](../kwara/adstxt.py) 存進 `scan_runs.ads_txt_json` 的解析結果，輸出兩類 cluster。這層的訊號來源和前面都不同：前面各層抓的是「誰部署了這個網站」，這層抓的是「**錢付給誰**」。

### `by_template` — 逐字節相同的 ads.txt

兩個以上落地網域回傳 `raw_sha256` 完全相同的 `ads.txt`。這是本層最強的訊號：同一份變現模板被複製到多個域，實務上就是同一個操作者的部署流程。

### `by_account` — 共用 DIRECT 帳號，但必須頻率加權

同一組 `(adsystem, seller_id)` 出現在 2 個以上網域。**只收 `DIRECT` 行**——`RESELLER` 是下游供應鏈轉售，不是發布者自己的收款帳號，收進來只會製造雜訊。

但「共用廣告帳號」本身有一個致命的誤判來源：**變現代管商**。一家代管商會把同一組帳號套用到旗下所有客戶網站，這些網站彼此毫無關係。所以每筆 cluster 帶一個 `tier`。

### tier 的判定基準是全資料庫足跡，不是本案

這一點是 2026-08-05 修正的核心，值得說明踩過的坑。原本的 `breadth_ratio` = 該帳號涵蓋的域數 ÷ 本案有可解析 `ads.txt` 的域數，低於門檻就判 `operator`。問題是**分母綁在本案語料上，而「本案」是分析師剛好載入了什麼**：

- 語料窄 → 帳號的真實廣度被藏住。`aralego|par-8A22…` 在只有 QSH 域名的案件裡看起來只涵蓋 8 個域、判為 operator；但它在同一個資料庫裡實際橫跨 **18 個 apex**，包含 bigpublisher2、family1 這些毫無關聯的主流農場
- 語料寬且同質 → 真正無所不在的中介反而掉到門檻以下。`kargo|8955` 涵蓋 23 個域、breadth 0.719 < 0.8，被判為 operator

同一個帳號、同一個世界，換個案件組成就換一種判定。所以 tier 改為以**全資料庫足跡**（`global_apex_count`）決定，並且用**可註冊域（apex）**計數——`redacted139.operatorhub.example` 與 `operatorhub.example` 是同一項資產，算一個。

| tier | 條件 | 解讀 |
|---|---|---|
| `manager` | **每個載體都宣告了 `MANAGERDOMAIN`**；或名列 `MAJOR_AD_EXCHANGES`；或 breadth_ratio ≥ `ADS_TXT_MANAGER_BREADTH`；或載體多數配對共用同一疊 ads.txt；或 `global_apex_count` ≥ `ADS_TXT_MANAGER_MIN_APEXES` | 代管商／轉售網路，**不是**同操作者訊號 |
| `operator` | `global_apex_count` ≤ `ADS_TXT_OPERATOR_MAX_APEXES` | 全庫範圍內確實稀有，**強訊號** |
| `uncertain` | 介於兩者之間 | 本機證據判不出來，**據實回報而非猜測**（見 §十二 原則 6） |

**`operator` 必須被「賺到」**。舊版的預設值是 operator——沒有任何降級規則觸發就宣告同操作者，這正是 23 域的中介被判成強訊號的原因。強主張應該要求正面證據，不是預設值。

### `MANAGERDOMAIN` 為什麼排在所有門檻前面

上表第一個條件跟其餘四個性質不同：它不是推論，是**網站自己的聲明**。

`MANAGERDOMAIN` 是 ads.txt 規格裡的變數，意思是「我的廣告由第三方代管」。一個網站這樣宣告，等於說「這份檔案裡的帳號屬於代管商，不屬於我」——**這是對自己不利的自白**，可信度遠高於任何門檻推估，也高於 SSP 在 sellers.json 裡的 `seller_type`（那是對己有利的方向，實測已證實不可信）。

規則刻意嚴格：**必須「每一個」載體網域都宣告代管才降級**。只要有一個載體是自營的，那個帳號就可能真的是該操作者自己的，問題就該保持開放。

實測威力：在合併語料的案件上，operator-tier 從 72 筆降到 4 筆，其中 160 筆是被這條規則降級的。它一次殺掉了三種門檻都殺不掉的假象——兩個大型發布商共用數百個帳號，而兩者都自承被代管。

覆蓋率是它的限制：本機案件資料中 111 筆 ads.txt 只有 2 筆宣告了 `MANAGERDOMAIN`。但那 2 筆恰好是雜訊的最大來源。**有宣告時是決定性的，沒宣告時什麼也不說。**

另外兩個實作細節：

- 分母 `case_domains` 只計「`status == 'ok'` 且真的有 records」的網域——403 或空白的 `ads.txt` 不該灌水分母
- 載體配對的模板連結率原本用 `all()`（全部配對都連結才降級），一個 ads.txt 特別薄的載體就能讓整條規則失效。實測 23 域帳號的配對連結率落在 0.65–0.81，永遠到不了 1.0。已改為比例門檻 `ADS_TXT_TEMPLATE_PAIR_RATIO`

**這是必須保留的契約**：`by_account` 不做加權就直接呈現，等於把「同一家代管商的客戶」宣告成「同一個操作者」。

### 實測普及度（`reference_prevalence`）

上面所有門檻都在試圖**推估**一件可以直接**測量**的事：這個帳號在正常網站中有多常見。

比率型判定需要「正常網站」的參照母體，而調查語料全部都是嫌疑者。2026-08-05 掃了 5,232 個一般發布商的 ads.txt 建出這份母體（95,560 個帳號），存在 `discovery/data/`，由 [prevalence.py](../kwara/prevalence.py) 載入。帳號出現率 ≥ `ADS_TXT_COMMODITY_PREVALENCE`（預設 0.5%）即判 manager。

兩條必須保留的語意：

- **這份表是選用的。** 機器上沒有時 `prevalence.load()` 回傳 `None`，tier 乾淨退回門檻判定。分析不會因為缺少一份參考資料而失敗，也不會因此把所有帳號都當成罕見。
- **「未見」不等於「罕見」。** 母體沒看過的帳號回傳 `None` 而非 `0.0`。母體只涵蓋八家 SSP 的發布商，涵蓋不到的東西很多；把缺失當成 0 會把每個未知帳號靜默升格成強訊號。

實測效果（合併語料案件的 operator-tier 筆數）：

```
原始（本案 breadth）           193
改用全庫 apex 足跡              72
加上 MANAGERDOMAIN 自白           4
加上實測普及度                    1   ← triplet1 三兄弟的 AdSense 帳號
```

那最後一筆的普及度是「未見」——它不是靠普及度存活的，是靠既有規則（全庫 3 個 apex）。這正是上面第二條語意的意義：測不到的東西，就讓其他證據說話。

### 仍然沒解決的

參照母體本身有偏誤：它是八家 SSP 的發布商名單，不是全網隨機樣本，偏向程式化廣告的發布商。`sellers.json` 的 `seller_type` 曾被寄望能提供權威判定，**實測證實不可用**（gliacloud 把 3,916 筆全標 `PUBLISHER`、Google 96.8 萬筆零 `INTERMEDIARY`）——只能單向採信自承 INTERMEDIARY 的那方。

---

## 十二、貫穿整個分析層的設計原則

整個分析層遵循六條規則。它們是「必須保留的契約」的核心子集——重構時最容易被靜悄悄破壞，而且破壞了測試不一定會紅：

1. **Schema 完整最重要**——每個聚合函式都用 `JOIN scan_runs ON sr.id = (... ORDER BY id DESC LIMIT 1)` 確保拿到「latest done」記錄；snapshot join 時還要過濾 `capture_status = 'ok'`，避免失敗的重截圖蓋掉成功的證據。
2. **跨模組去重靠常數，不靠字串**——`PLATFORM_*` 是 symbol；任何 typo 會炸成 `NameError` 而不是靜悄悄寫到錯桶子。
3. **可驗證 ＞ 演算法巧妙**——每個 cluster 都帶 `domains`/`urls`/`posts` 清單，分析師可以順著回頭看原始證據；而不是只給 cluster ID。
4. **Threshold 不掛 magic number**——所有可調參數（`PARAM_KEY_MIN_POSTS`、`PARAM_VALUE_HASH_THRESHOLD`、`CLOAKING_BODY_SIZE_DIFF`、`ADS_TXT_MANAGER_BREADTH` 等）都集中在 [config.py](../kwara/config.py) 或模組頂部常數，能調、能解釋、能在報告裡引用。
5. **Fingerprint 必須有 invocation context**——`gtag/ga/fbq/ttq/_lt/twq/clarity` 等函式呼叫、vendor URL host、或 `dataLayer` 字面量；新增 fingerprint 必須附負面測試。
6. **不自動下協同行為判定**——任何協同門檻（同一支內容 N 分鐘內 ≥ M 個帳號發出、時間分布 z-score）只要 tune 到單一 dataset 就會 overfit 那個 operator。kwara 輸出原始分布與 cluster，判定留給分析師的跨案例脈絡。這是設計立場，不是尚未實作的功能。

這六條合起來，目標只有一個：**讓拿到 ZIP 證據封包的第三方，不需要信任 kwara、也不需要信任分析師，就能重現我們的所見。**
