# Taiwan-targeted content farm domains

*中文說明在下方。*

A list of **450 domains** in **9 clusters** of content farms aimed at Taiwanese readers, as of **2026-10-02**. The file is `domains.csv`.

The format follows the list of "Borderless" (無邊界) content farm domains published by Doublethink Lab (台灣民主實驗室), so the two can be compared directly: [Doublethink Lab list](https://docs.google.com/spreadsheets/d/e/2PACX-1vThDEAV-Tbag0yYP8X2ZpIhu6xiEmgWANjfu6XWqVVjkLNsjjZpCpjf8i9RL2axKo8N_esPq7tL73kG/pubhtml?gid=0&single=true).

## Columns

| Column | Meaning |
|---|---|
| `apex domain` | The registrable domain. |
| `webpage hosting main content` | The host that serves the content we captured. Usually the apex domain itself; 8 rows use a subdomain. |
| `status (as of last check)` | `available` if our most recent browser capture loaded the page; `unavailable` if it did not. This is not a statement about the site today. |
| `contains jp.` / `contains br.` | `TRUE` if we observed a `jp.` or `br.` subdomain for this domain in our captures. `FALSE` only means we did not observe one; Doublethink Lab's list flags many more. |
| `cluster` | The cluster the domain belongs to (see below). |
| `last check` | Date of our most recent browser capture of the domain (YYYY-MM-DD). |

## Clusters

| Code | Domains | Notes |
|---|---|---|
| `alpha` | 374 | Corresponds to Doublethink Lab's "Borderless" (無邊界) list; 367 of these 374 domains also appear in that list. We use the name only as Doublethink Lab published it and do not attribute the cluster to any company. |
| `gamma` | 31 | |
| `looker-17` | 23 | |
| `family-01` | 9 | |
| `beta` | 3 | |
| `ezvivi` | 3 | |
| `enews` | 3 | |
| `eatmary` | 2 | |
| `twqiang` | 2 | |

## How domains were included

- A cluster is a set of domains that we found sharing operator-controlled identifiers in our own browser captures (for example analytics and advertising account IDs, or infrastructure that only that operator's sites load). The identifiers themselves are not published here.
- Only clusters with strong evidence are included. Candidate groups that we have not verified are left out.
- Every listed domain had at least one successful browser capture by us. Seven domains in our records without such a capture are left out.

## Limits

- Domains change hands and are repurposed. A domain in this list may belong to someone else by the time you read it.
- This list says which domains belong to the same operator cluster. It does not say anything about the accuracy of their content, the operator's identity, or any intent to influence.
- Corrections are welcome as GitHub issues.

---

# 台灣向內容農場網域清單

以台灣讀者為對象的內容農場，**9 個群、450 個網域**，資料時點 **2026-10-02**，檔案為 `domains.csv`。

格式比照台灣民主實驗室公開的「無邊界」內容農場清單，方便兩者直接對照：[台灣民主實驗室清單](https://docs.google.com/spreadsheets/d/e/2PACX-1vThDEAV-Tbag0yYP8X2ZpIhu6xiEmgWANjfu6XWqVVjkLNsjjZpCpjf8i9RL2axKo8N_esPq7tL73kG/pubhtml?gid=0&single=true)。

## 欄位

| 欄位 | 意義 |
|---|---|
| `apex domain` | 可註冊的主網域。 |
| `webpage hosting main content` | 我們擷取到內容的主機。通常就是主網域；有 8 列是子網域。 |
| `status (as of last check)` | 我們最近一次用瀏覽器擷取時頁面有載入為 `available`，沒有載入為 `unavailable`。不代表網站今天的狀態。 |
| `contains jp.` / `contains br.` | 我們的擷取中看過這個網域有 `jp.` 或 `br.` 子網域就是 `TRUE`。`FALSE` 只代表我們沒看過，台灣民主實驗室的清單標出的數量多得多。 |
| `cluster` | 網域所屬的群（見下表）。 |
| `last check` | 我們最近一次用瀏覽器擷取這個網域的日期。 |

## 群

| 代號 | 網域數 | 說明 |
|---|---|---|
| `alpha` | 374 | 對應台灣民主實驗室的「無邊界」清單，這 374 個中有 367 個也在該清單上。我們只沿用台灣民主實驗室公開的名稱，不把這個群歸屬給任何公司。 |
| `gamma` | 31 | |
| `looker-17` | 23 | |
| `family-01` | 9 | |
| `beta` | 3 | |
| `ezvivi` | 3 | |
| `enews` | 3 | |
| `eatmary` | 2 | |
| `twqiang` | 2 | |

## 收錄方式

- 一個群是指我們在自己的瀏覽器擷取中，發現共用經營者自有識別碼的一組網域，例如分析與廣告帳號 ID，或只有該經營者網站才會載入的基礎設施。識別碼本身不在此公開。
- 只收證據充分的群，尚未驗證的候選群不收。
- 每個網域都至少有一次我們自己的瀏覽器擷取成功。紀錄中有 7 個網域沒有成功擷取，不收。

## 限制

- 網域會易手、改作他用。你讀到時，清單上的網域可能已屬於別人。
- 這份清單只說明哪些網域屬於同一個經營群，不涉及內容是否正確、經營者身分，或任何影響意圖。
- 歡迎以 GitHub issue 提出更正。
