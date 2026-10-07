"""Read-only SQL access to the advisory database for the agent.

The agent writes the query; SQLite does every count, sum, and average, so
numbers in an answer come from the database rather than the model's reading.

Guardrails: the file is opened read-only (mode=ro plus query_only), only a
single SELECT or WITH statement is accepted, rows are capped, long text is
clipped, and a progress handler aborts runaway queries.
"""

from __future__ import annotations

import re
import sqlite3

from src.db import DB_PATH

MAX_ROWS = 100
MAX_CELL_CHARS = 300
# SQLite VM steps between progress-handler checks, and how many checks before abort
PROGRESS_STEP = 10_000
MAX_PROGRESS_CHECKS = 500

SCHEMA_NOTES = """\
Tables (SQLite):
- advisories(id 'SA-0183', title, url, published_date, description, affected_products)
- cves(cve_id, advisory_id -> advisories.id, cvss_score REAL 0-10, cvss_vector,
       cwe_id 'CWE-78', attack_vector 'NETWORK'|'ADJACENT_NETWORK'|'LOCAL'|'PHYSICAL',
       attack_complexity 'LOW'|'HIGH', privileges_required 'NONE'|'LOW'|'HIGH',
       epss_score REAL 0-1, epss_percentile REAL 0-1, kev_listed INTEGER 0|1,
       kev_date_added 'YYYY-MM-DD', kev_vendor 'Arista'|'Apache'|'GNU'|...)
- ai_classifications(advisory_id, affected_component, attack_surface
       'management-plane'|'control-plane'|'data-plane'|'local-only'|'unknown',
       vulnerability_category, root_cause_category, mitigation_quality)
       One row per advisory.
- semgrep_rules(cwe_id, rule_id, rule_yaml, rationale)

Gotchas:
- Arista advisories also cover upstream CVEs (Log4j, Bash, OpenSSL, Linux kernel)
  and reposted VMware-era VeloCloud ones. For Arista's own exploited CVEs use
  kev_listed = 1 AND kev_vendor = 'Arista'; kev_listed = 1 alone includes upstream.
- One advisory has many CVEs. To count advisories from the cves table use
  COUNT(DISTINCT advisory_id); COUNT(*) on cves counts CVEs.
- published_date is free text in mixed formats ('September 22, 2026',
  'September 29th 2014', '2026-09-23T03:26:26Z') and is empty for some
  advisories. For a year, match the four digits: published_date LIKE '%2026%'.
- cvss_score, cwe_id, attack_vector, and epss_score can be NULL.
- CVSS severity bands: Critical >= 9.0, High 7.0-8.9, Medium 4.0-6.9, Low < 4.0.
"""

_ALLOWED_START = re.compile(r"^\s*(select|with)\b", re.IGNORECASE)


def run_readonly_sql(sql: str) -> dict:
    """Run one SELECT against the database and return rows, or an error."""
    statement = sql.strip().rstrip(";").strip()
    if not _ALLOWED_START.match(statement):
        return {"error": "Only a single SELECT (or WITH ... SELECT) statement is allowed."}
    if ";" in statement:
        return {"error": "Only one statement per call."}

    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    conn.execute("PRAGMA query_only = ON")
    checks = {"n": 0}

    def _abort_if_slow():
        checks["n"] += 1
        return 1 if checks["n"] > MAX_PROGRESS_CHECKS else 0

    conn.set_progress_handler(_abort_if_slow, PROGRESS_STEP)
    try:
        cur = conn.execute(statement)
        columns = [d[0] for d in cur.description or []]
        fetched = cur.fetchmany(MAX_ROWS + 1)
    except sqlite3.Error as e:
        return {"error": f"SQL error: {e}", "sql": statement}
    finally:
        conn.close()

    def clip(v):
        if isinstance(v, str) and len(v) > MAX_CELL_CHARS:
            return v[:MAX_CELL_CHARS] + "..."
        return v

    rows = [[clip(v) for v in row] for row in fetched[:MAX_ROWS]]
    return {
        "sql": statement,
        "columns": columns,
        "rows": rows,
        "row_count": len(rows),
        "truncated": len(fetched) > MAX_ROWS,
    }
