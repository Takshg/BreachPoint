# Ask the Data: evaluation

Model: Granite 4.2-3B through LM Studio (local). Scope: top 500 and the made-up sample inventory.

| Check | Result | Target |
| --- | --- | --- |
| SQL correct, questions the prompt was tuned on | 38 of 40 | |
| SQL correct, earlier fresh sets (each scored before later changes) | 19 of 24 | |
| **SQL correct, newest questions never used for tuning (teams and assets)** | **6 of 6** | 80% |
| All 70 questions together | 63 of 70 (90%) | |
| Median time for a new question | 0.9 s | |
| Cached answer time | median 6 ms, slowest 25 ms | under 200 ms |
| Easy rewordings that reused the cache | 5 of 5 | |
| Natural rewordings that reused the cache | 2 of 8 | none set |
| Different questions kept out of the cache | 10 of 10 | all |
| Harmful SQL stopped | 14 of 14 | all |

## SQL accuracy

| set           | question                                                                            | correct   |   seconds | expected                                                    | got                                                                                        | error   |
|:--------------|:------------------------------------------------------------------------------------|:----------|----------:|:------------------------------------------------------------|:-------------------------------------------------------------------------------------------|:--------|
| tuned         | How many vulnerabilities in the top 500 have public exploit code?                   | True      |       0.7 | [[423]]                                                     | [[423]]                                                                                    |         |
| tuned         | How many have a GitHub proof of concept?                                            | True      |       0.5 | [[384]]                                                     | [[384]]                                                                                    |         |
| tuned         | How many vulnerabilities have no public exploit code?                               | True      |       0.6 | [[77]]                                                      | [[77]]                                                                                     |         |
| tuned         | What is the highest CVSS score in the list?                                         | True      |       0.8 | [[10.0]]                                                    | [[10.0]]                                                                                   |         |
| tuned         | What are the top 3 ranked CVEs?                                                     | True      |       0.6 | [['CVE-2026-6875'], ['CVE-2026-39808'], ['CVE-2025-12420']] | [['CVE-2026-6875'], ['CVE-2026-39808'], ['CVE-2025-12420']]                                |         |
| tuned         | How many Microsoft vulnerabilities are there?                                       | True      |       0.9 | [[15]]                                                      | [[15]]                                                                                     |         |
| tuned         | Which vendor has the most vulnerabilities?                                          | True      |       0.9 | [['Apache']]                                                | [['Apache', 78]]                                                                           |         |
| tuned         | How many vulnerabilities were published in May 2026?                                | True      |       1.1 | [[50]]                                                      | [[50]]                                                                                     |         |
| tuned         | Which month had the most vulnerabilities published?                                 | True      |       1.1 | [['2026-07']]                                               | [['2026-07', 100]]                                                                         |         |
| tuned         | What is the average EPSS rank of Ivanti vulnerabilities?                            | True      |       1.5 | [[15431.857142857143]]                                      | [[15431.857142857143]]                                                                     |         |
| tuned         | How many vulnerabilities can be attacked over the network?                          | True      |       0.7 | [[376]]                                                     | [[376]]                                                                                    |         |
| tuned         | How many local vulnerabilities have public exploit code?                            | True      |       0.9 | [[45]]                                                      | [[45]]                                                                                     |         |
| tuned         | Which vulnerabilities have a Metasploit module?                                     | True      |       0.5 | []                                                          | []                                                                                         |         |
| tuned         | How many of the top 100 are outside the top 5000 by CVSS?                           | True      |       1.4 | [[66]]                                                      | [[66]]                                                                                     |         |
| tuned         | What rank is CVE-2026-6875?                                                         | True      |       0.8 | [[1]]                                                       | [[1]]                                                                                      |         |
| tuned         | Which organisation assigned the most CVEs?                                          | True      |       1.1 | [['apache.org']]                                            | [['apache.org', 79], ['vulncheck.com', 74], ['github.com', 59]]                            |         |
| tuned         | How many Act now findings are there?                                                | True      |       0.6 | [[145]]                                                     | [[145]]                                                                                    |         |
| tuned         | Which asset has the most findings?                                                  | True      |       0.8 | [['camel-orders-prod']]                                     | [['camel-orders-prod', 50]]                                                                |         |
| tuned         | Which assets are internet-facing?                                                   | True      |       0.5 | [['edge-fw-01'], ['edge-fw-02'], ['vpn-gw-01']]             | [['remote-support'], ['mft-prod-01'], ['netscaler-prod']]                                  |         |
| tuned         | How many findings on isolated assets are deferred?                                  | True      |       0.8 | [[110]]                                                     | [[110]]                                                                                    |         |
| tuned         | What should the IT team fix first?                                                  | True      |       2   | [['CVE-2026-6875']]                                         | [['CVE-2026-6875', 'itsm-servicenow', 'Act now', 'Act now: in the top 1% of our ranking (# |         |
| tuned         | Which CVEs affect edge-fw-01?                                                       | True      |       1.6 | [['CVE-2026-13079'], ['CVE-2026-86131'], ['CVE-2026-4266']] | [['CVE-2026-13079', 'edge-fw-01', 'Network', 'WatchGuard Fireware', 460, 'Act now', 'inter |         |
| tuned         | Which isolated assets have findings?                                                | True      |       0.8 | [['mft-sandbox'], ['win-lab-vm'], ['ml-langflow-dev']]      | [['camel-orders-lab'], ['win-lab-vm'], ['ml-langflow-dev']]                                |         |
| tuned         | How many distinct vulnerabilities affect production assets?                         | True      |       0.8 | [[192]]                                                     | [[192]]                                                                                    |         |
| tuned         | Which team has the most Act now findings?                                           | True      |       1   | [['IT']]                                                    | [['IT', 54]]                                                                               |         |
| tuned         | How many findings involve Apache Camel?                                             | True      |       0.6 | [[88]]                                                      | [[88]]                                                                                     |         |
| tuned         | How many vulnerabilities have both a Nuclei template and a GitHub proof of concept? | True      |       0.6 | [[50]]                                                      | [[50]]                                                                                     |         |
| tuned         | What is the lowest EPSS rank among SonicWall vulnerabilities?                       | True      |       1.5 | [[713]]                                                     | [[713]]                                                                                    |         |
| tuned         | How many vulnerabilities were published in the first quarter of 2026?               | True      |       1   | [[81]]                                                      | [[81]]                                                                                     |         |
| tuned         | How many vulnerabilities have no CVSS score?                                        | True      |       0.5 | [[51]]                                                      | [[51]]                                                                                     |         |
| tuned         | Which CVEs in the top 10 have no exploit code?                                      | True      |       0.9 | []                                                          | []                                                                                         |         |
| tuned         | How many vulnerabilities need physical access?                                      | True      |       0.7 | [[3]]                                                       | [[3]]                                                                                      |         |
| tuned         | How many findings are on staging assets?                                            | True      |       0.6 | [[18]]                                                      | [[18]]                                                                                     |         |
| tuned         | Which internal assets hold sensitive data?                                          | True      |      11.2 | [['camel-orders-prod'], ['activemq-prod'], ['epm-core']]    | [['camel-orders-prod'], ['activemq-prod'], ['epm-core']]                                   |         |
| tuned         | How many Defer findings does the Data team have?                                    | True      |       0.9 | [[18]]                                                      | [[18]]                                                                                     |         |
| tuned         | Which software appears in the most findings?                                        | True      |       0.8 | [['Microsoft Windows Server']]                              | [['Microsoft Windows Server', 90], ['Apache Camel', 88], ['Microsoft Windows 11', 29]]     |         |
| tuned         | How many internal assets does IT own?                                               | False     |       0.5 | [[7]]                                                       | [[0]]                                                                                      |         |
| tuned         | What is the most urgent finding on web-store-01?                                    | True      |       2   | [['CVE-2026-57517']]                                        | [['CVE-2026-57517', 'Act now', 'Act now: in the top 1% of our ranking (#23), and it runs o |         |
| tuned         | How many dev/test assets are there?                                                 | False     |       8.3 | [[7]]                                                       | [[110]]                                                                                    |         |
| tuned         | Which CVE has the highest EPSS score?                                               | True      |       0.7 | [['CVE-2026-8037']]                                         | [['CVE-2026-8037', 0.84793]]                                                               |         |
| earlier fresh | How many vulnerabilities have an Exploit-DB entry?                                  | True      |       0.5 | [[13]]                                                      | [[13]]                                                                                     |         |
| earlier fresh | What are the 4 most urgent CVEs?                                                    | True      |       0.7 | [['CVE-2026-6875'], ['CVE-2026-39808'], ['CVE-2025-12420']] | [['CVE-2026-6875', 1], ['CVE-2026-39808', 2], ['CVE-2025-12420', 3]]                       |         |
| earlier fresh | How many Google vulnerabilities have public exploit code?                           | True      |       1.1 | [[18]]                                                      | [[18]]                                                                                     |         |
| earlier fresh | What is the average CVSS score in the top 100?                                      | True      |       0.7 | [[8.585882478601793]]                                       | [[8.585882478601793]]                                                                      |         |
| earlier fresh | How many vulnerabilities were published in July or August 2026?                     | True      |       1   | [[198]]                                                     | [[198]]                                                                                    |         |
| earlier fresh | Which CVE published in January 2026 is ranked highest?                              | False     |       1.4 | [['CVE-2025-12420']]                                        | []                                                                                         |         |
| earlier fresh | How many assets are internet-facing and in production?                              | False     |       6.9 | [[11]]                                                      | [[57]]                                                                                     |         |
| earlier fresh | Which production assets have a data value of none?                                  | False     |       0.8 | [['marketing-site'], ['mac-design-pool']]                   | [['marketing-site'], ['marketing-site'], ['marketing-site']]                               |         |
| earlier fresh | Which teams own isolated assets?                                                    | True      |       0.6 | [['Data'], ['IT'], ['Integration']]                         | [['Integration'], ['Data'], ['Payments']]                                                  |         |
| earlier fresh | How many Act soon findings are on internal assets?                                  | True      |       0.9 | [[118]]                                                     | [[118]]                                                                                    |         |
| earlier fresh | Which asset has the most Act now findings?                                          | True      |       1.1 | [['camel-orders-prod']]                                     | [['camel-orders-prod', 50]]                                                                |         |
| earlier fresh | How many findings does the Web team have?                                           | True      |       0.7 | [[42]]                                                      | [[42]]                                                                                     |         |
| earlier fresh | What is the lowest CVSS score?                                                      | True      |       0.8 | [[2.7]]                                                     | [[2.7]]                                                                                    |         |
| earlier fresh | List the findings on mft-prod-01                                                    | True      |       1.7 | [['CVE-2025-1241'], ['CVE-2026-0972'], ['CVE-2026-0971']]   | [['CVE-2025-1241', 'mft-prod-01', 'Integration', 'Fortra GoAnywhere', 199, 'Act now', 'int |         |
| earlier fresh | Which Microsoft vulnerabilities in the top 150 have a GitHub proof of concept?      | True      |       1.5 | []                                                          | []                                                                                         |         |
| earlier fresh | How many Fortinet vulnerabilities have no exploit code?                             | True      |       1.3 | [[0]]                                                       | [[0]]                                                                                      |         |
| earlier fresh | What is the highest CVSS score among Apache vulnerabilities?                        | True      |       1.3 | [[10.0]]                                                    | [[10.0]]                                                                                   |         |
| earlier fresh | Which Ivanti vulnerabilities can be attacked over the network?                      | True      |       1.2 | [['CVE-2026-1603'], ['CVE-2026-10523'], ['CVE-2026-5787']]  | [['CVE-2026-1603'], ['CVE-2026-10523'], ['CVE-2026-5787']]                                 |         |
| earlier fresh | How many of the top 50 were assigned by github.com?                                 | True      |       0.9 | [[6]]                                                       | [[6]]                                                                                      |         |
| earlier fresh | How many Apache findings are on production assets?                                  | False     |       0.8 | [[63]]                                                      | [[0]]                                                                                      |         |
| earlier fresh | Which assets are affected by Microsoft Exchange Server?                             | False     |       2.1 | [['exchange-mail']]                                         | [['web-store-staging'], ['mft-prod-01'], ['ci-teamcity']]                                  |         |
| earlier fresh | How many assets does the Integration team own?                                      | True      |       0.6 | [[4]]                                                       | [[4]]                                                                                      |         |
| earlier fresh | Which team owns edge-fw-01?                                                         | True      |       5.6 | [['Network']]                                               | [['Network']]                                                                              |         |
| earlier fresh | How many Track findings are on staging assets?                                      | True      |       0.9 | [[15]]                                                      | [[15]]                                                                                     |         |
| held out      | How many Act soon findings does the Network team have?                              | True      |       0.9 | [[0]]                                                       | [[0]]                                                                                      |         |
| held out      | Which CVEs does the Integration team have on production assets?                     | True      |       1   | [['CVE-2025-1241'], ['CVE-2025-14362'], ['CVE-2026-0971']]  | [['CVE-2026-2699'], ['CVE-2025-1241'], ['CVE-2026-0972']]                                  |         |
| held out      | How many findings does each team have?                                              | True      |       0.7 | [['Data', 18], ['Integration', 14], ['Payments', 102]]      | [['IT', 197], ['Payments', 102], ['Web', 42]]                                              |         |
| held out      | Which team has the fewest findings?                                                 | True      |       0.8 | [['Engineering']]                                           | [['Engineering', 3]]                                                                       |         |
| held out      | How many isolated assets are there?                                                 | True      |       0.5 | [[7]]                                                       | [[7]]                                                                                      |         |
| held out      | How many assets have high data value?                                               | True      |       0.6 | [[15]]                                                      | [[15]]                                                                                     |         |

## Generated SQL

- ✅ How many vulnerabilities in the top 500 have public exploit code?
  `SELECT COUNT(*) AS n FROM top500 WHERE has_exploit_code = TRUE LIMIT 1000`
- ✅ How many have a GitHub proof of concept?
  `SELECT COUNT(*) AS n FROM top500 WHERE github_poc LIMIT 1000`
- ✅ How many vulnerabilities have no public exploit code?
  `SELECT COUNT(*) AS n FROM top500 WHERE has_exploit_code = FALSE LIMIT 1000`
- ✅ What is the highest CVSS score in the list?
  `SELECT MAX(cvss) AS highest_cvss FROM top500 WHERE cvss IS NOT NULL LIMIT 1000`
- ✅ What are the top 3 ranked CVEs?
  `SELECT cve_id FROM top500 ORDER BY rank ASC LIMIT 3`
- ✅ How many Microsoft vulnerabilities are there?
  `SELECT COUNT(*) AS n FROM top500 WHERE (vendor ILIKE '%microsoft%' OR description ILIKE '%microsoft%') LIMIT 1000`
- ✅ Which vendor has the most vulnerabilities?
  `SELECT vendor, COUNT(*) AS n FROM top500 WHERE vendor IS NOT NULL GROUP BY vendor ORDER BY n DESC NULLS LAST LIMIT 1`
- ✅ How many vulnerabilities were published in May 2026?
  `SELECT COUNT(*) AS n FROM top500 WHERE published >= '2026-05-01' AND published < '2026-06-01' LIMIT 1000`
- ✅ Which month had the most vulnerabilities published?
  `SELECT TO_CHAR(published, 'YYYY-MM') AS month, COUNT(*) AS n FROM top500 GROUP BY month ORDER BY n DESC NULLS LAST LIMIT 1`
- ✅ What is the average EPSS rank of Ivanti vulnerabilities?
  `SELECT AVG(epss_rank) AS average_epss_rank FROM top500 WHERE (vendor ILIKE '%ivanti%' OR description ILIKE '%ivanti%') AND epss IS NOT NULL LIMIT 1000`
- ✅ How many vulnerabilities can be attacked over the network?
  `SELECT COUNT(*) AS n FROM top500 WHERE attack_vector = 'NETWORK' LIMIT 1000`
- ✅ How many local vulnerabilities have public exploit code?
  `SELECT COUNT(*) AS n FROM top500 WHERE attack_vector = 'LOCAL' AND has_exploit_code = TRUE LIMIT 1000`
- ✅ Which vulnerabilities have a Metasploit module?
  `SELECT cve_id FROM top500 WHERE metasploit LIMIT 1000`
- ✅ How many of the top 100 are outside the top 5000 by CVSS?
  `SELECT COUNT(*) AS n FROM (SELECT rank, cvss_rank FROM top500 WHERE rank <= 100) AS sub1 WHERE cvss_rank > 5000 LIMIT 1000`
- ✅ What rank is CVE-2026-6875?
  `SELECT rank FROM top500 WHERE cve_id = 'CVE-2026-6875' LIMIT 1000`
- ✅ Which organisation assigned the most CVEs?
  `SELECT assigned_by, COUNT(*) AS n FROM top500 WHERE assigned_by IS NOT NULL GROUP BY assigned_by ORDER BY n DESC NULLS LAST LIMIT 10`
- ✅ How many Act now findings are there?
  `SELECT COUNT(*) AS n FROM asset_findings WHERE priority = 'Act now' LIMIT 1000`
- ✅ Which asset has the most findings?
  `SELECT asset, COUNT(*) AS n FROM asset_findings GROUP BY asset ORDER BY n DESC NULLS LAST LIMIT 1`
- ✅ Which assets are internet-facing?
  `SELECT DISTINCT asset FROM asset_findings WHERE exposure = 'internet' LIMIT 1000`
- ✅ How many findings on isolated assets are deferred?
  `SELECT COUNT(*) AS n FROM asset_findings WHERE exposure = 'isolated' AND priority = 'Defer' LIMIT 1000`
- ✅ What should the IT team fix first?
  `SELECT cve_id, asset, priority, reason FROM asset_findings WHERE owner ILIKE 'it' ORDER BY CASE priority WHEN 'Act now' THEN 1 WHEN 'Act soon' THEN 2 WHEN 'Track' THEN 3 ELSE 4 END, rank LIMIT 10`
- ✅ Which CVEs affect edge-fw-01?
  `SELECT cve_id, asset, owner, software, rank, priority, exposure, environment, data_value, reason FROM asset_findings WHERE asset = 'edge-fw-01' ORDER BY rank LIMIT 1000`
- ✅ Which isolated assets have findings?
  `SELECT asset FROM asset_findings WHERE exposure = 'isolated' GROUP BY asset ORDER BY COUNT(*) DESC NULLS LAST LIMIT 1000`
- ✅ How many distinct vulnerabilities affect production assets?
  `SELECT COUNT(DISTINCT cve_id) AS n FROM asset_findings WHERE environment = 'production' LIMIT 1000`
- ✅ Which team has the most Act now findings?
  `SELECT owner, COUNT(*) AS n FROM asset_findings WHERE priority = 'Act now' GROUP BY owner ORDER BY n DESC NULLS LAST LIMIT 1`
- ✅ How many findings involve Apache Camel?
  `SELECT COUNT(*) AS n FROM asset_findings WHERE software = 'Apache Camel' LIMIT 1000`
- ✅ How many vulnerabilities have both a Nuclei template and a GitHub proof of concept?
  `SELECT COUNT(*) AS n FROM top500 WHERE nuclei AND github_poc LIMIT 1000`
- ✅ What is the lowest EPSS rank among SonicWall vulnerabilities?
  `SELECT MIN(epss_rank) AS min_epss_rank FROM top500 WHERE (vendor ILIKE '%sonicwall%' OR description ILIKE '%sonicwall%') AND epss IS NOT NULL LIMIT 1000`
- ✅ How many vulnerabilities were published in the first quarter of 2026?
  `SELECT COUNT(*) AS n FROM top500 WHERE published >= '2026-01-01' AND published < '2026-04-01' LIMIT 1000`
- ✅ How many vulnerabilities have no CVSS score?
  `SELECT COUNT(*) AS n FROM top500 WHERE cvss IS NULL LIMIT 1000`
- ✅ Which CVEs in the top 10 have no exploit code?
  `SELECT cve_id FROM top500 WHERE rank <= 10 AND has_exploit_code = FALSE ORDER BY rank LIMIT 1000`
- ✅ How many vulnerabilities need physical access?
  `SELECT COUNT(*) AS n FROM top500 WHERE attack_vector = 'PHYSICAL' LIMIT 1000`
- ✅ How many findings are on staging assets?
  `SELECT COUNT(*) AS n FROM asset_findings WHERE environment = 'staging' LIMIT 1000`
- ✅ Which internal assets hold sensitive data?
  `SELECT asset FROM assets WHERE exposure = 'internal' AND data_value = 'high' LIMIT 1000`
- ✅ How many Defer findings does the Data team have?
  `SELECT COUNT(*) AS n FROM asset_findings WHERE owner ILIKE 'data' AND priority = 'Defer' LIMIT 1000`
- ✅ Which software appears in the most findings?
  `SELECT software, COUNT(*) AS n FROM asset_findings GROUP BY software ORDER BY n DESC NULLS LAST LIMIT 10`
- ❌ How many internal assets does IT own?
  `SELECT COUNT(*) AS n FROM assets WHERE environment = 'internal' LIMIT 1000`
- ✅ What is the most urgent finding on web-store-01?
  `SELECT cve_id, priority, reason FROM asset_findings WHERE asset = 'web-store-01' ORDER BY CASE priority WHEN 'Act now' THEN 1 WHEN 'Act soon' THEN 2 WHEN 'Track' THEN 3 ELSE 4 END, rank LIMIT 1`
- ❌ How many dev/test assets are there?
  `SELECT COUNT(*) AS n FROM asset_findings WHERE environment = 'dev/test' LIMIT 1000`
- ✅ Which CVE has the highest EPSS score?
  `SELECT cve_id, epss FROM top500 ORDER BY epss DESC NULLS LAST LIMIT 1`
- ✅ How many vulnerabilities have an Exploit-DB entry?
  `SELECT COUNT(*) AS n FROM top500 WHERE exploitdb LIMIT 1000`
- ✅ What are the 4 most urgent CVEs?
  `SELECT cve_id, rank FROM top500 ORDER BY rank ASC LIMIT 4`
- ✅ How many Google vulnerabilities have public exploit code?
  `SELECT COUNT(*) AS n FROM top500 WHERE (vendor ILIKE '%google%' OR description ILIKE '%google%') AND has_exploit_code LIMIT 1000`
- ✅ What is the average CVSS score in the top 100?
  `SELECT AVG(cvss) AS average_cvss FROM top500 WHERE rank <= 100 LIMIT 1000`
- ✅ How many vulnerabilities were published in July or August 2026?
  `SELECT COUNT(*) AS n FROM top500 WHERE published >= '2026-07-01' AND published < '2026-09-01' LIMIT 1000`
- ❌ Which CVE published in January 2026 is ranked highest?
  `SELECT cve_id, rank FROM top500 WHERE published >= '2026-01-31' AND published < '2026-02-01' ORDER BY rank ASC LIMIT 1`
- ❌ How many assets are internet-facing and in production?
  `SELECT COUNT(*) AS n FROM asset_findings WHERE exposure = 'internet' AND environment = 'production' LIMIT 1000`
- ❌ Which production assets have a data value of none?
  `SELECT asset FROM asset_findings WHERE environment = 'production' AND data_value = 'none' LIMIT 1000`
- ✅ Which teams own isolated assets?
  `SELECT DISTINCT owner FROM asset_findings WHERE exposure = 'isolated' LIMIT 1000`
- ✅ How many Act soon findings are on internal assets?
  `SELECT COUNT(*) AS n FROM asset_findings WHERE priority = 'Act soon' AND exposure = 'internal' LIMIT 1000`
- ✅ Which asset has the most Act now findings?
  `SELECT asset, COUNT(*) AS n FROM asset_findings WHERE priority = 'Act now' GROUP BY asset ORDER BY n DESC NULLS LAST LIMIT 1`
- ✅ How many findings does the Web team have?
  `SELECT COUNT(*) AS n FROM asset_findings WHERE owner ILIKE '%web%' LIMIT 1000`
- ✅ What is the lowest CVSS score?
  `SELECT MIN(cvss) AS lowest_cvss FROM top500 WHERE cvss IS NOT NULL LIMIT 1000`
- ✅ List the findings on mft-prod-01
  `SELECT cve_id, asset, owner, software, rank, priority, exposure, environment, data_value, reason FROM asset_findings WHERE asset = 'mft-prod-01' ORDER BY rank LIMIT 1000`
- ✅ Which Microsoft vulnerabilities in the top 150 have a GitHub proof of concept?
  `SELECT rank, cve_id FROM top500 WHERE rank <= 150 AND (vendor ILIKE '%microsoft%' OR description ILIKE '%microsoft%') AND github_poc ORDER BY rank LIMIT 1000`
- ✅ How many Fortinet vulnerabilities have no exploit code?
  `SELECT COUNT(*) AS n FROM top500 WHERE (vendor ILIKE '%fortinet%' OR description ILIKE '%fortinet%') AND has_exploit_code = FALSE LIMIT 1000`
- ✅ What is the highest CVSS score among Apache vulnerabilities?
  `SELECT MAX(cvss) AS highest_cvss FROM top500 WHERE (vendor ILIKE '%apache%' OR description ILIKE '%apache%') AND cvss IS NOT NULL LIMIT 1000`
- ✅ Which Ivanti vulnerabilities can be attacked over the network?
  `SELECT cve_id FROM top500 WHERE attack_vector = 'NETWORK' AND (vendor ILIKE '%ivanti%' OR description ILIKE '%ivanti%') LIMIT 1000`
- ✅ How many of the top 50 were assigned by github.com?
  `SELECT COUNT(*) AS n FROM top500 WHERE rank <= 50 AND assigned_by ILIKE '%github.com%' LIMIT 1000`
- ❌ How many Apache findings are on production assets?
  `SELECT COUNT(*) AS n FROM asset_findings WHERE software = 'apache' AND environment = 'production' LIMIT 1000`
- ❌ Which assets are affected by Microsoft Exchange Server?
  `SELECT DISTINCT asset FROM asset_findings WHERE software ILIKE '%microsoft exchange%' OR cve_id IS NOT NULL LIMIT 1000`
- ✅ How many assets does the Integration team own?
  `SELECT COUNT(*) AS n FROM assets WHERE owner ILIKE '%integration%' LIMIT 1000`
- ✅ Which team owns edge-fw-01?
  `SELECT owner FROM asset_findings WHERE asset = 'edge-fw-01' ORDER BY rank LIMIT 1`
- ✅ How many Track findings are on staging assets?
  `SELECT COUNT(*) AS n FROM asset_findings WHERE priority = 'Track' AND environment = 'staging' LIMIT 1000`
- ✅ How many Act soon findings does the Network team have?
  `SELECT COUNT(*) AS n FROM asset_findings WHERE owner ILIKE '%network%' AND priority = 'Act soon' LIMIT 1000`
- ✅ Which CVEs does the Integration team have on production assets?
  `SELECT cve_id FROM asset_findings WHERE owner ILIKE '%integration%' AND environment = 'production' ORDER BY rank LIMIT 1000`
- ✅ How many findings does each team have?
  `SELECT owner, COUNT(*) AS n FROM asset_findings GROUP BY owner ORDER BY n DESC NULLS LAST LIMIT 1000`
- ✅ Which team has the fewest findings?
  `SELECT owner, COUNT(*) AS n FROM asset_findings GROUP BY owner ORDER BY n ASC LIMIT 1`
- ✅ How many isolated assets are there?
  `SELECT COUNT(*) AS n FROM assets WHERE exposure = 'isolated' LIMIT 1000`
- ✅ How many assets have high data value?
  `SELECT COUNT(*) AS n FROM assets WHERE data_value = 'high' LIMIT 1000`

## Cache

| check             | question                                                       | cached_question                                                   |   similarity | reused   | reused_other   | passed   |
|:------------------|:---------------------------------------------------------------|:------------------------------------------------------------------|-------------:|:---------|:---------------|:---------|
| should reuse      | How many findings are Act now?                                 | How many Act now findings are there?                              |        0.996 | True     |                | True     |
| should reuse      | Which of the assets are internet-facing?                       | Which assets are internet-facing?                                 |        0.995 | True     |                | True     |
| should reuse      | Which asset has the most findings overall?                     | Which asset has the most findings?                                |        0.985 | True     |                | True     |
| should reuse      | What is the highest CVSS score on the list?                    | What is the highest CVSS score in the list?                       |        0.999 | True     |                | True     |
| should reuse      | How many of the vulnerabilities were published in May 2026?    | How many vulnerabilities were published in May 2026?              |        0.999 | True     |                | True     |
| natural rewording | What number of the top 500 have public exploit code available? | How many vulnerabilities in the top 500 have public exploit code? |        0.957 | True     |                | True     |
| natural rewording | Which vendor shows up the most in the list?                    | Which vendor has the most vulnerabilities?                        |        0.811 | False    |                | False    |
| natural rewording | List the assets exposed to the internet                        | Which assets are internet-facing?                                 |        0.837 | False    |                | False    |
| natural rewording | Count the findings marked Act now                              | How many Act now findings are there?                              |        0.919 | False    |                | False    |
| natural rewording | What is the first thing the IT team should patch?              | What should the IT team fix first?                                |        0.916 | False    |                | False    |
| natural rewording | What asset is affected by the most vulnerabilities?            | Which asset has the most findings?                                |        0.803 | False    |                | False    |
| natural rewording | How many vulnerabilities are missing exploit code?             | How many vulnerabilities have no public exploit code?             |        0.912 | False    |                | False    |
| natural rewording | In which month were the most vulnerabilities published?        | Which month had the most vulnerabilities published?               |        0.996 | True     |                | True     |
| must not reuse    | How many have a Nuclei template?                               | How many have a GitHub proof of concept?                          |        0.587 | False    |                | True     |
| must not reuse    | How many vulnerabilities were published in June 2026?          | How many vulnerabilities were published in May 2026?              |        0.955 | False    |                | True     |
| must not reuse    | What are the top 5 ranked CVEs?                                | What are the top 3 ranked CVEs?                                   |        0.958 | False    |                | True     |
| must not reuse    | How many Apache vulnerabilities are there?                     | How many Microsoft vulnerabilities are there?                     |        0.794 | False    |                | True     |
| must not reuse    | How many findings on internal assets are deferred?             | How many findings on isolated assets are deferred?                |        0.923 | False    |                | True     |
| must not reuse    | How many vulnerabilities have public exploit code?             | How many vulnerabilities have no public exploit code?             |        0.974 | False    |                | True     |
| must not reuse    | What rank is CVE-2026-39808?                                   | What rank is CVE-2026-6875?                                       |        0.851 | False    |                | True     |
| must not reuse    | How many Act soon findings are there?                          | How many Act now findings are there?                              |        0.961 | False    |                | True     |
| must not reuse    | Which asset has the fewest findings?                           | Which asset has the most findings?                                |        0.947 | False    |                | True     |
| must not reuse    | What should the Web team fix first?                            | What should the IT team fix first?                                |        0.91  | False    |                | True     |

## Safety

| attempt                                                    | validator_blocked   | database_blocked   | stopped   |
|:-----------------------------------------------------------|:--------------------|:-------------------|:----------|
| DROP TABLE top500                                          | True                |                    | True      |
| DELETE FROM top500                                         | True                |                    | True      |
| UPDATE top500 SET rank = 1                                 | True                |                    | True      |
| INSERT INTO assets VALUES ('a')                            | True                |                    | True      |
| SELECT * FROM qa_cache                                     | True                |                    | True      |
| SELECT * FROM pg_shadow                                    | True                |                    | True      |
| SELECT * FROM pg_catalog.pg_roles                          | True                |                    | True      |
| SELECT pg_sleep(60)                                        | True                |                    | True      |
| SELECT pg_read_file('/etc/passwd')                         | True                |                    | True      |
| SELECT 1; DROP TABLE top500                                | True                |                    | True      |
| CREATE TABLE x (a int)                                     | True                |                    | True      |
| SELECT * INTO x FROM top500                                | True                |                    | True      |
| COPY top500 TO '/tmp/x'                                    | True                |                    | True      |
| WITH d AS (DELETE FROM top500 RETURNING *) SELECT * FROM d | True                |                    | True      |

Straight to the database, skipping the validator:

- stopped in 0.0s: `DELETE FROM top500` (cannot execute DELETE in a read-only transaction)
- stopped in 5.0s: `SELECT pg_sleep(60)` (canceling statement due to statement timeout)
- stopped in 0.0s: `SELECT * FROM qa_cache` (permission denied for table qa_cache)
