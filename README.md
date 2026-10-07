# Advisory Intel

**Arista PSIRT Advisory Intelligence Platform.** It analyzes Arista's entire public security advisory history to surface recurring weakness patterns (CWE clustering, component heat maps, severity vs exploitability trends) and closes the feedback loop to prevention via Semgrep SAST rules.

## The Thesis

PSIRT teams triage CVEs one at a time. This tool steps back and asks: *what do 183 advisories, taken together, tell us about where the same classes of bugs keep recurring?* Recurring CWE patterns aren't individual vulnerability problems; they're systemic coding practice problems that SAST rules should catch before code ships.

**The feedback loop**: Advisories → Pattern Analysis → Prevention Rules

## Agentic Mode (Strands Agents)

The platform has two modes: a deterministic **batch pipeline** for ETL runs (same input, same output, auditable), and a **tool-using agent** that wraps the same pipeline stages as tools and decides which to call, and in what order, to answer a plain-English question. The agent is read-mostly on purpose: it queries and analyzes, and anything that would change state belongs behind a human approval step.

```bash
# Set up Python 3.10+ venv (required for Strands SDK)
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Interactive agent
export $(cat .env | grep -v '#' | xargs)
python agent.py

# Single query
python agent.py "Which CWE patterns recur the most and which lack Semgrep coverage?"
```

**What the agent does differently from the pipeline:**

| Batch Pipeline | Agentic Mode |
|---|---|
| Runs all stages in fixed order | LLM decides which tools to call based on the question |
| `python main.py pipeline` | "What new advisories match our top CWE patterns?" |
| Same output every time | Chains tools, cross-references data, recommends actions |
| No interaction | Conversational: ask follow-ups, drill into specifics |

**Example (real output, 2026-10-01, trimmed):**

```
$ .venv/bin/python agent.py "How many distinct advisories have at least one CVE in CISA KEV, and which are they?"
Tool #1: run_sql
Let me fix that query:
Tool #2: run_sql
Tool #3: run_sql

9 distinct advisories have at least one CVE listed in CISA's KEV catalog:
| SA-0004 | April 9th 2014     | CVE-2014-0160                              |
| SA-0006 | September 29th 2014| CVE-2014-7169, CVE-2014-6278, CVE-2014-6271 |
| SA-0070 | January 31st, 2022 | CVE-2021-44228, CVE-2021-45046             |
| ...                                                                       |
| SA-0183 | September 22, 2026 | CVE-2026-93952                             |
```

The count comes from `COUNT(DISTINCT advisory_id)` in SQLite, not from the model
reading rows (see "Why the agent has a SQL tool" below). Note the agent fixing
its own failed query on the second call.

### Agent Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     STRANDS AGENT LAYER                          │
│                                                                  │
│  User ──▶ Agent (Claude Haiku 4.5) ──▶ Reasoning Loop           │
│                    │                                             │
│                    ├──▶ scrape_advisories        (src/scraper)   │
│                    ├──▶ enrich_cves              (src/enricher)  │
│                    ├──▶ classify_advisories      (src/ai)        │
│                    ├──▶ query_advisory_db        (src/db)        │
│                    ├──▶ run_sql (read-only)      (src/agent)     │
│                    ├──▶ analyze_patterns         (src/analyzer)  │
│                    ├──▶ generate_insights        (src/ai)        │
│                    ├──▶ generate_semgrep_rules   (src/rules)     │
│                    ├──▶ scan_infrastructure      (ComplianceGuard)
│                    └──▶ cross_reference_advisory (bridge)        │
│                         _with_infrastructure                     │
│                                                                  │
│  The LLM decides which tools to call and in what order.          │
│  Tools wrap existing pipeline modules; no code rewrite needed.  │
├──────────────────────────────────────────────────────────────────┤
│                  COMPLIANCEGUARD BRIDGE                           │
│                                                                  │
│  advisory-intel ◄──────────────────────► ComplianceGuard         │
│  (CWE patterns)    CWE-to-policy map    (container compliance)  │
│                                                                  │
│  CWE-78  ──▶ no-privileged-containers + drop-all-capabilities   │
│  CWE-269 ──▶ no-privileged-containers + no-new-privileges       │
│  CWE-732 ──▶ read-only-root-filesystem                          │
│                                                                  │
│  Finds where advisory weakness patterns AND infrastructure      │
│  compliance gaps overlap; that's where real risk lives.         │
├──────────────────────────────────────────────────────────────────┤
│                     OTEL TRACING                                 │
│                                                                  │
│  Agent ──▶ TracerProvider ──▶ data/agent_traces.log (default)    │
│                           ──▶ stderr (OTEL_CONSOLE=1)            │
│                           ──▶ OTLPExporter   (Grafana/Tempo)    │
│                                                                  │
│  Every tool call, reasoning step, and query gets a trace span.  │
├──────────────────────────────────────────────────────────────────┤
│                        EVAL SUITE                                │
│                                                                  │
│  Tool Selection ··········· Does the agent pick the right tool?  │
│  Data Accuracy ············ Does it return real numbers?          │
│  Hallucination Resistance · Does it refuse to fabricate data?    │
│  Multi-Step Reasoning ····· Can it chain tools for complex Qs?   │
│  Escalation Judgment ······ Does it prioritize correctly?        │
│  Cross-Project Bridge ····· Does it bridge advisory + infra?     │
│  Numeric Accuracy ········· Are counts exact (SQL ground truth)? │
│                                                                  │
│  Result: 25/26 passed on 2026-10-01 (see below)                  │
└──────────────────────────────────────────────────────────────────┘
```

### Running Evals

```bash
python -m evals.eval_agent            # Full suite (26 tests, about $0.56, own $1.00 cap)
python -m evals.eval_agent --quick    # Tool selection only
python -m evals.eval_agent --numeric  # Counting questions vs SQL ground truth
# Results saved to data/eval_results.json
```

The one failure in the last full run was the infrastructure-scan case with Docker
stopped: the agent correctly said the scanner was "unavailable", which the test
didn't accept yet. That phrase is now accepted.

### Why the agent has a SQL tool

LLMs miscount. Asked how many advisories have a CVE in CISA KEV, the agent once
answered 7 while listing all 9: it was deduplicating and counting tool output in
its head. The fix is structural, not a patch per question:

- `run_sql` gives the agent read-only SQL (SQLite `mode=ro` + `query_only`, one
  SELECT per call, row cap, query timeout), with schema notes such as "count
  advisories with COUNT(DISTINCT advisory_id)".
- The system prompt forbids computing numbers; every number must come from a
  tool result. Every query is recorded in the trace log, and the agent is told
  to show its SQL (it doesn't always; the trace log is the reliable record).
- `--numeric` checks 10 counting questions against SQL ground truth.

| Setup | Numeric evals passed | Cost of the 10 questions |
|---|---|---|
| Before: no SQL tool, no rule | 4 / 10 | $0.15 |
| After: `run_sql` + rule | 10 / 10 | $0.08 |

The remaining risk is a wrong query rather than wrong arithmetic, and every
query is in the trace log so a person can check it.

## Cost Controls

Claude calls are cheap here (Haiku 4.5; a full classification run of all 183
advisories is about $0.25), but an agent loop or eval run can multiply that
quickly. Every run is capped:

- **$0.50 per run** for classification, the Insights tab, and each agent
  session (`src/ai/budget.py`). Before each call, the worst case (estimated input
  plus the full `max_tokens` of output) is checked against what the run has
  already spent; if it could cross the cap, the call is not sent. Actual cost is
  recorded from the API's token usage.
- The full eval suite gets its own cap (default $1.00, `EVAL_BUDGET_USD`);
  cases the cap cuts off are reported as SKIPPED, not FAIL.
- Classification stops on the first API rejection (for example, a billing
  error) instead of retrying every advisory.
- Evals clear the agent's history between cases. A shared history resent every
  earlier tool output on each call, which multiplied cost.
- Override the per-run cap with `CLAUDE_RUN_BUDGET_USD`.

### OTEL Tracing

```bash
# Spans go to data/agent_traces.log by default; print them live with:
OTEL_CONSOLE=1 python agent.py "What are the top CWE patterns?"

# Send traces to Grafana/Tempo
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 python agent.py
```

## What It Does

1. **Scrapes** all 183 published Arista security advisories (CSAF JSON + advisory detail pages)
2. **Enriches** 346 CVEs with NVD (CVSS vectors, CWE IDs), EPSS (exploitability probability), and CISA KEV (active exploitation) data
3. **Classifies** each advisory with Claude AI: affected EOS component, attack surface (management/control/data plane), vulnerability category, root cause, mitigation quality
4. **Analyzes** patterns across the full history: CWE clustering, component heat maps, severity distribution, yearly trends, CVSS vs EPSS scatter
5. **Generates** AI-powered program-level insights with specific SDLC recommendations
6. **Produces** Semgrep SAST rules derived from the top recurring CWEs, closing the PSIRT-to-SDLC feedback loop

## Quick Start

```bash
pip3 install -r requirements.txt

# Set up API key for AI features (classification, insights, agent)
cp .env.example .env
# Edit .env with your Anthropic API key, then load it:
set -a; . ./.env; set +a

# Run the full pipeline
python main.py pipeline

# Generate SAST rules from patterns
python main.py rules

# Start the dashboard
python main.py serve
# Open http://localhost:8000
```

### Refreshing the data

Arista's site serves a bot challenge to scripted requests, now including the
CSAF JSON files, so `python main.py scrape` works from cached link files
(`data/advisory_list.json`, `data/csaf_links.json`). To pick up new advisories,
extract the newest entries and their CSAF JSON through a real browser session
(Playwright), add them to those files, then run `scrape`, `enrich`, and
`classify`. Only new or unclassified records are processed, so a refresh costs
cents.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        DATA PIPELINE                            │
│                                                                 │
│  Arista CSAF JSON ─┐                                           │
│                     ├──▶ Scraper ──▶ SQLite DB                  │
│  Advisory Pages ────┘       │                                   │
│                             ▼                                   │
│                     NVD API (CVSS, CWE)                         │
│                     EPSS API (exploitability)   ──▶ Enrichment  │
│                     CISA KEV (active exploits)                  │
│                             │                                   │
│                             ▼                                   │
│                     Claude AI ──▶ Classification                │
│                       (component, attack surface, root cause)   │
│                             │                                   │
│                             ▼                                   │
│                     Pattern Analysis ──▶ Insights               │
│                             │                                   │
│                             ▼                                   │
│                     Semgrep Rule Generator ──▶ SAST Rules       │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                        PRESENTATION                             │
│                                                                 │
│  FastAPI ──▶ Dashboard (5 tabs)                                 │
│    Overview  │ Key charts + findings at a glance                │
│    Analysis  │ 6 interactive charts (CWE, severity, trend...)   │
│    Insights  │ AI-generated SDLC recommendations                │
│    SAST Rules│ Semgrep rules grouped by CWE + Export YAML       │
│    Advisories│ Searchable/filterable table of all 183           │
└─────────────────────────────────────────────────────────────────┘
```

## Commands

| Command | Description |
|---------|-------------|
| `python main.py scrape` | Scrape advisories from cached CSAF/detail data |
| `python main.py enrich` | Enrich CVEs from NVD, EPSS, CISA KEV |
| `python main.py classify` | Classify advisories with Claude AI |
| `python main.py rules` | Generate Semgrep rules from CWE patterns |
| `python main.py pipeline` | Run scrape + enrich + classify in sequence |
| `python main.py serve` | Start the dashboard (default: port 8000) |
| `python agent.py` | Interactive agentic analyst (Strands) |
| `python agent.py "query"` | Single-query agent mode |
| `python -m evals.eval_agent` | Run full eval suite (26 tests) |
| `python -m evals.eval_agent --quick` | Run tool selection evals only |
| `python -m evals.eval_agent --numeric` | Run counting evals against SQL ground truth |

## Project Structure

```
advisory-intel/
├── main.py                          # CLI entry point (batch pipeline)
├── agent.py                         # Agentic entry point (Strands agent)
├── requirements.txt                 # Python dependencies
├── .env                             # ANTHROPIC_API_KEY (not committed)
├── data/
│   ├── advisory_intel.db            # SQLite database (all state)
│   ├── eval_results.json            # Latest eval run results
│   ├── agent_traces.log             # Agent trace spans (not committed)
│   ├── csaf_links.json              # 41 CSAF JSON download URLs
│   ├── csaf_batch1.json             # Downloaded CSAF documents (batch 1)
│   ├── csaf_batch2.json             # Downloaded CSAF documents (batch 2)
│   ├── advisory_list.json           # 184 advisory summaries (all pages)
│   ├── detail_batch_latest.json     # SA-0173 to SA-0182 detail extractions
│   └── detail_batch_all.json        # SA-0001 to SA-0172 detail extractions
├── evals/
│   └── eval_agent.py                # 7-category eval suite (26 test cases)
└── src/
    ├── db.py                        # SQLite schema (4 tables)
    ├── agent/
    │   ├── tools.py                 # 10 @tool wrappers for Strands agent
    │   ├── sql_tool.py              # Read-only SQL for the agent + schema notes
    │   └── tracing.py               # OTEL tracing (log file, console, or OTLP)
    ├── scraper/
    │   └── arista.py                # CSAF JSON + advisory list scraper
    ├── enricher/
    │   ├── nvd.py                   # NVD API v2 (CVSS, CWE)
    │   ├── epss.py                  # FIRST.org EPSS API
    │   └── kev.py                   # CISA KEV catalog
    ├── ai/
    │   ├── classifier.py            # Claude AI classification + insights
    │   └── budget.py                # Per-run spend cap (classifier + agent hook)
    ├── analyzer/
    │   └── patterns.py              # SQL-based pattern analysis (7 queries)
    ├── rules/
    │   └── generator.py             # Semgrep rule generation from CWE data
    ├── api/
    │   └── app.py                   # FastAPI app + REST endpoints
    └── dashboard/
        └── templates/
            └── dashboard.html       # Single-page dashboard (Chart.js)
```

## Database Schema

**4 tables** in SQLite with WAL mode:

- `advisories`: 183 records: id, title, url, published_date, description, affected_products
- `cves`: 346 records: cve_id, advisory_id, cvss_score/vector/version, cwe_id, attack_vector/complexity/privileges, epss_score/percentile, kev_listed/date/vendor
- `ai_classifications`: 183 records: advisory_id, affected_component, attack_surface, vulnerability_category, root_cause_category, mitigation_quality
- `semgrep_rules`: 9 records: cwe_id, cwe_name, rule_id, rule_yaml, rationale

## Data Coverage

| Metric | Count |
|--------|-------|
| Advisories scraped | 183 |
| CVEs tracked | 346 |
| NVD enriched (CVSS/CWE) | 121 (from NVD) + 121 (from CSAF/detail pages) |
| With CVSS scores | 242 (70%) |
| With CWE IDs | 203 (59%) |
| With EPSS scores | 334 (97%) |
| In CISA KEV | 12 (3 Arista, 9 upstream or third-party) |
| AI classified | 183 (100%) |
| Semgrep rules generated | 9 (covering 6 CWE categories) |

## Key Findings (from the data)

- **KEV status has to override the scores.** Three of Arista's own CVEs are in CISA KEV, all added in 2026, and all three had EPSS under 0.02. One (SA-0137) is CVSS 5.8. The other 9 KEV matches are upstream or third-party CVEs that Arista advisories respond to (Log4j, Bash, OpenSSL, the Linux kernel including Copy Fail, and a reposted VMware-era VeloCloud CVE); they are counted separately.
- **CWE-78 (OS Command Injection)** is the #1 recurring weakness: 11 occurrences, avg CVSS 8.2. 8 of the 11 were published in 2026, mostly in the NG Firewall and VeloCloud product lines.
- **VeloCloud Orchestrator on-prem** had two CVSS 10.0, KEV-listed issues eight weeks apart (SA-0144, SA-0183) with the same described impact.
- **82% of CVEs with full CVSS vectors are network-reachable** (94 of 115); 45% (52 of 115) are also low complexity with no privileges required.
- **Management plane** is the dominant attack surface (81 of 183 classified advisories).
- **Advisory volume is up sharply:** 2014 to 2024 averaged about 8 advisories a year; 2025 had 29 and 2026 had 51 through September.

Data as of 2026-10-01 (through SA-0184).

## Known Limitations

- **Dates:** `published_date` comes in three text formats and is empty for 14
  advisories, so the dashboard's yearly trend counts by CVE year as a proxy.
  The volume figures above were recounted from advisory dates.
- **CWE coverage:** 41% of CVEs have no CWE (NVD had data for only 121 of 346),
  so the CWE ranking undercounts.
- **AI tags:** classifications use fixed category lists and JSON-only output,
  and the parser handles wrapped or multi-object replies, but the tags have not
  yet been checked against a hand-labeled sample.
- **Semgrep rules:** Python templates written from CWE patterns. They are not
  deployed in any CI pipeline and have not been run against Arista code.
- **Upstream CVEs in advisories:** Arista publishes advisories for upstream
  open-source issues, often to say which products are not affected. Those CVEs
  are in the `cves` table too. KEV counts are split using the KEV catalog's
  `vendorProject` field; other aggregates (CWE ranking, severity mix) still
  include upstream CVEs. An earlier version reported "12 Arista CVEs in KEV";
  the correct figure is 3.
- **Public data only:** nothing here reflects Arista's internal process; root
  causes behind repeated issues are not visible from advisories.

## Tech Stack

- **Python 3.12**: core pipeline (3.10+ required for Strands SDK)
- **Strands Agents SDK**: agentic framework with `@tool` decorator, model-driven reasoning loop
- **SQLite** (WAL mode): single-file database, no external DB needed
- **FastAPI + Uvicorn**: REST API + dashboard server
- **Chart.js 4.4**: interactive charts (CDN, no build step)
- **Claude Haiku 4.5**: advisory classification, insights, and agent reasoning (~$0.25 for a full classification run; every run capped at $0.50)
- **OpenTelemetry**: agent decision audit trail (log file by default, console, or OTLP/Grafana)
- **Docker SDK**: ComplianceGuard bridge for live container scanning
- **Semgrep YAML**: output format for SAST rules

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard |
| `/api/summary` | GET | Stats (advisory/CVE/enriched/classified counts) |
| `/api/analysis` | GET | Full pattern analysis (CWE, severity, trends, etc.) |
| `/api/insights` | GET | Generate AI insights (calls Claude) |
| `/api/advisories` | GET | Advisory list with CVE stats |
| `/api/advisories/{id}` | GET | Single advisory detail with CVEs + classifications |
| `/api/rules` | GET | All generated Semgrep rules |
| `/api/rules/generate` | POST | Regenerate rules from current CWE data |
| `/api/rules/export` | GET | Download all rules as single YAML file |
| `/api/pipeline/full` | POST | Run complete pipeline |
