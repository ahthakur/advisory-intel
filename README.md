# Advisory Intel

**Arista PSIRT Advisory Intelligence Platform** — Analyzes Arista's entire public security advisory history to surface recurring weakness patterns (CWE clustering, component heat maps, severity vs exploitability trends) and closes the feedback loop to prevention via Semgrep SAST rules.

## The Thesis

PSIRT teams triage CVEs one at a time. This tool steps back and asks: *what do 181 advisories, taken together, tell us about where the same classes of bugs keep recurring?* Recurring CWE patterns aren't individual vulnerability problems — they're systemic coding practice problems that SAST rules should catch before code ships.

**The feedback loop**: Advisories → Pattern Analysis → Prevention Rules

## Agentic Mode (Strands Agents)

The platform has two modes: a **batch pipeline** for ETL runs, and an **autonomous agent** that wraps the same pipeline stages as tools and reasons about which to invoke based on natural language queries.

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
| No interaction | Conversational — ask follow-ups, drill into specifics |

**Example session:**

```
You > Which CVEs should be top priority?
Agent > [calls query_advisory_db] → [analyzes CVSS + EPSS + KEV signals]

  TIER 0 (48h): CVE-2026-16812 (CVSS 10.0 + KEV + CWE-78),
                CVE-2021-44228 (EPSS 0.99999 + KEV)
  TIER 1 (7d):  CVE-2024-3094 (CVSS 10.0, EPSS 0.86)
  ...
  Recommendation: Patch TIER 0 immediately. Generate Semgrep rules
  for the 4 uncovered CWE categories.

You > Generate the rules for CWE-290
Agent > [calls generate_semgrep_rules(cwe_filter="CWE-290")] → rule YAML output
```

### Agent Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     STRANDS AGENT LAYER                          │
│                                                                  │
│  User ──▶ Agent (Claude Haiku 4.5) ──▶ Reasoning Loop           │
│                    │                                             │
│                    ├──▶ scrape_advisories      (src/scraper)     │
│                    ├──▶ enrich_cves            (src/enricher)    │
│                    ├──▶ classify_advisories    (src/ai)          │
│                    ├──▶ query_advisory_db      (src/db)          │
│                    ├──▶ analyze_patterns       (src/analyzer)    │
│                    ├──▶ generate_insights      (src/ai)          │
│                    └──▶ generate_semgrep_rules (src/rules)       │
│                                                                  │
│  The LLM decides which tools to call and in what order.          │
│  Tools wrap existing pipeline modules — no code rewrite needed.  │
├──────────────────────────────────────────────────────────────────┤
│                        EVAL SUITE                                │
│                                                                  │
│  Tool Selection ··········· Does the agent pick the right tool?  │
│  Data Accuracy ············ Does it return real numbers?          │
│  Hallucination Resistance · Does it refuse to fabricate data?    │
│  Multi-Step Reasoning ····· Can it chain tools for complex Qs?   │
│  Escalation Judgment ······ Does it prioritize correctly?        │
│                                                                  │
│  Result: 13/14 passed (93%)                                      │
└──────────────────────────────────────────────────────────────────┘
```

### Running Evals

```bash
python -m evals.eval_agent            # Full suite (14 tests, ~3 min)
python -m evals.eval_agent --quick    # Tool selection only
# Results saved to data/eval_results.json
```

## What It Does

1. **Scrapes** all 181 published Arista EOS security advisories (CSAF JSON + advisory detail pages)
2. **Enriches** 345 CVEs with NVD (CVSS vectors, CWE IDs), EPSS (exploitability probability), and CISA KEV (active exploitation) data
3. **Classifies** each advisory with Claude AI — affected EOS component, attack surface (management/control/data plane), vulnerability category, root cause, mitigation quality
4. **Analyzes** patterns across the full history: CWE clustering, component heat maps, severity distribution, yearly trends, CVSS vs EPSS scatter
5. **Generates** AI-powered program-level insights with specific SDLC recommendations
6. **Produces** Semgrep SAST rules derived from the top recurring CWEs — the PSIRT-to-SDLC feedback loop

## Quick Start

```bash
pip3 install -r requirements.txt

# Set up API key for AI features (classification + insights)
cp .env.example .env
# Edit .env with your Anthropic API key

# Run the full pipeline
python main.py pipeline

# Generate SAST rules from patterns
python main.py rules

# Start the dashboard
python main.py serve
# Open http://localhost:8000
```

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
│    Advisories│ Searchable/filterable table of all 181           │
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
| `python -m evals.eval_agent` | Run full eval suite (14 tests) |
| `python -m evals.eval_agent --quick` | Run tool selection evals only |

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
│   ├── csaf_links.json              # 40 CSAF JSON download URLs
│   ├── csaf_batch1.json             # Downloaded CSAF documents (batch 1)
│   ├── csaf_batch2.json             # Downloaded CSAF documents (batch 2)
│   ├── advisory_list.json           # 182 advisory summaries (all pages)
│   ├── detail_batch_latest.json     # SA-0173 to SA-0182 detail extractions
│   └── detail_batch_all.json        # SA-0001 to SA-0172 detail extractions
├── evals/
│   └── eval_agent.py                # 5-category eval suite (14 test cases)
└── src/
    ├── db.py                        # SQLite schema (4 tables)
    ├── agent/
    │   └── tools.py                 # 7 @tool wrappers for Strands agent
    ├── scraper/
    │   └── arista.py                # CSAF JSON + advisory list scraper
    ├── enricher/
    │   ├── nvd.py                   # NVD API v2 (CVSS, CWE)
    │   ├── epss.py                  # FIRST.org EPSS API
    │   └── kev.py                   # CISA KEV catalog
    ├── ai/
    │   └── classifier.py            # Claude AI classification + insights
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

- `advisories` — 181 records: id, title, url, published_date, description, affected_products
- `cves` — 345 records: cve_id, advisory_id, cvss_score/vector/version, cwe_id, attack_vector/complexity/privileges, epss_score/percentile, kev_listed/date
- `ai_classifications` — 174 records: advisory_id, affected_component, attack_surface, vulnerability_category, root_cause_category, mitigation_quality
- `semgrep_rules` — 9 records: cwe_id, cwe_name, rule_id, rule_yaml, rationale

## Data Coverage

| Metric | Count |
|--------|-------|
| Advisories scraped | 181 |
| CVEs tracked | 345 |
| NVD enriched (CVSS/CWE) | 120 (from NVD) + 121 (from CSAF/detail pages) |
| With CVSS scores | 241 (70%) |
| With CWE IDs | 202 (59%) |
| With EPSS scores | 333 (97%) |
| In CISA KEV | 11 |
| AI classified | 174 (96%) |
| Semgrep rules generated | 9 (covering 6 CWE categories) |

## Key Findings (from the data)

- **CWE-78 (OS Command Injection)** is the #1 recurring weakness — 11 occurrences, avg CVSS 8.2
- **81% of vulnerabilities** are network-accessible with low complexity and no authentication required
- **Management plane** is the dominant attack surface (75 of 174 classified advisories)
- **11 CVEs** appear in CISA's Known Exploited Vulnerabilities catalog (actively exploited in the wild)
- **2024-2026 shows a 3x acceleration** in advisory volume vs historical baseline

## Tech Stack

- **Python 3.12** — core pipeline (3.10+ required for Strands SDK)
- **Strands Agents SDK** — agentic framework with `@tool` decorator, model-driven reasoning loop
- **SQLite** (WAL mode) — single-file database, no external DB needed
- **FastAPI + Uvicorn** — REST API + dashboard server
- **Chart.js 4.4** — interactive charts (CDN, no build step)
- **Claude Haiku 4.5** — advisory classification, insights, and agent reasoning (~$0.25 for full pipeline run)
- **Semgrep YAML** — output format for SAST rules

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
