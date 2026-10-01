# Advisory Intel

**Arista PSIRT Advisory Intelligence Platform** — Analyzes Arista's entire public security advisory history to surface recurring weakness patterns (CWE clustering, component heat maps, severity vs exploitability trends) and closes the feedback loop to prevention via Semgrep SAST rules.

## The Thesis

PSIRT teams triage CVEs one at a time. This tool steps back and asks: *what do 183 advisories, taken together, tell us about where the same classes of bugs keep recurring?* Recurring CWE patterns aren't individual vulnerability problems — they're systemic coding practice problems that SAST rules should catch before code ships.

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
│                    ├──▶ scrape_advisories        (src/scraper)   │
│                    ├──▶ enrich_cves              (src/enricher)  │
│                    ├──▶ classify_advisories      (src/ai)        │
│                    ├──▶ query_advisory_db        (src/db)        │
│                    ├──▶ analyze_patterns         (src/analyzer)  │
│                    ├──▶ generate_insights        (src/ai)        │
│                    ├──▶ generate_semgrep_rules   (src/rules)     │
│                    ├──▶ scan_infrastructure      (ComplianceGuard)
│                    └──▶ cross_reference_advisory (bridge)        │
│                         _with_infrastructure                     │
│                                                                  │
│  The LLM decides which tools to call and in what order.          │
│  Tools wrap existing pipeline modules — no code rewrite needed.  │
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
│  compliance gaps overlap — that's where real risk lives.         │
├──────────────────────────────────────────────────────────────────┤
│                     OTEL TRACING                                 │
│                                                                  │
│  Agent ──▶ TracerProvider ──▶ ConsoleExporter (demo)             │
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
│                                                                  │
│  Result: 15/16 passed (94%)                                      │
└──────────────────────────────────────────────────────────────────┘
```

### Running Evals

```bash
python -m evals.eval_agent            # Full suite (16 tests, ~4 min)
python -m evals.eval_agent --quick    # Tool selection only
# Results saved to data/eval_results.json
```

### OTEL Tracing

```bash
# Console tracing (default — for demos)
python agent.py "What are the top CWE patterns?"

# Send traces to Grafana/Tempo
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 python agent.py
```

## What It Does

1. **Scrapes** all 183 published Arista security advisories (CSAF JSON + advisory detail pages)
2. **Enriches** 346 CVEs with NVD (CVSS vectors, CWE IDs), EPSS (exploitability probability), and CISA KEV (active exploitation) data
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
| `python -m evals.eval_agent` | Run full eval suite (16 tests) |
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
│   └── eval_agent.py                # 6-category eval suite (16 test cases)
└── src/
    ├── db.py                        # SQLite schema (4 tables)
    ├── agent/
    │   ├── tools.py                 # 9 @tool wrappers for Strands agent
    │   └── tracing.py               # OTEL tracing (console + OTLP export)
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

- `advisories` — 183 records: id, title, url, published_date, description, affected_products
- `cves` — 346 records: cve_id, advisory_id, cvss_score/vector/version, cwe_id, attack_vector/complexity/privileges, epss_score/percentile, kev_listed/date
- `ai_classifications` — 178 records: advisory_id, affected_component, attack_surface, vulnerability_category, root_cause_category, mitigation_quality
- `semgrep_rules` — 9 records: cwe_id, cwe_name, rule_id, rule_yaml, rationale

## Data Coverage

| Metric | Count |
|--------|-------|
| Advisories scraped | 183 |
| CVEs tracked | 346 |
| NVD enriched (CVSS/CWE) | 121 (from NVD) + 121 (from CSAF/detail pages) |
| With CVSS scores | 242 (70%) |
| With CWE IDs | 203 (59%) |
| With EPSS scores | 334 (97%) |
| In CISA KEV | 12 |
| AI classified | 178 (97%) |
| Semgrep rules generated | 9 (covering 6 CWE categories) |

## Key Findings (from the data)

- **KEV status has to override the scores.** 4 Arista CVEs were added to CISA KEV in 2026; 3 of the 4 have EPSS under 0.02, and one (SA-0137) is CVSS 5.8. Of 30 CVEs scored CVSS 9 or higher, only 4 are in KEV.
- **CWE-78 (OS Command Injection)** is the #1 recurring weakness: 11 occurrences, avg CVSS 8.2. 8 of the 11 were published in 2026, mostly in the NG Firewall and VeloCloud product lines.
- **VeloCloud Orchestrator on-prem** had two CVSS 10.0, KEV-listed issues eight weeks apart (SA-0144, SA-0183) with the same described impact.
- **82% of CVEs with full CVSS vectors are network-reachable** (94 of 115); 45% (52 of 115) are also low complexity with no privileges required.
- **Management plane** is the dominant attack surface (79 of 178 classified advisories).
- **Advisory volume is up sharply:** 2014 to 2024 averaged about 8 advisories a year; 2025 had 29 and 2026 had 51 through September.

Data as of 2026-10-01 (through SA-0184).

## Tech Stack

- **Python 3.12** — core pipeline (3.10+ required for Strands SDK)
- **Strands Agents SDK** — agentic framework with `@tool` decorator, model-driven reasoning loop
- **SQLite** (WAL mode) — single-file database, no external DB needed
- **FastAPI + Uvicorn** — REST API + dashboard server
- **Chart.js 4.4** — interactive charts (CDN, no build step)
- **Claude Haiku 4.5** — advisory classification, insights, and agent reasoning (~$0.25 for full pipeline run)
- **OpenTelemetry** — distributed tracing for agent decision audit trail (console or OTLP/Grafana)
- **Docker SDK** — ComplianceGuard bridge for live container scanning
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
