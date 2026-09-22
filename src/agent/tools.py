"""Strands agent tools — wraps the advisory-intel pipeline as callable tools."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Optional

from strands import tool

from src.db import get_connection, init_db


@tool
def scrape_advisories() -> str:
    """Scrape Arista PSIRT security advisories from cached CSAF feeds and advisory list.

    Run this to ingest new advisories into the database. Uses pre-cached link
    files from data/ directory (csaf_links.json and advisory_list.json).
    Returns a summary of what was scraped.
    """
    init_db()
    from src.scraper.arista import scrape_all
    asyncio.run(scrape_all())

    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) as c FROM advisories").fetchone()["c"]
    cve_count = conn.execute("SELECT COUNT(*) as c FROM cves").fetchone()["c"]
    conn.close()
    return f"Scrape complete. Database now has {total} advisories and {cve_count} CVEs."


@tool
def enrich_cves(source: str = "all") -> str:
    """Enrich CVEs with external threat intelligence data.

    Fetches CVSS scores from NVD, exploit probability from EPSS, and checks
    CISA Known Exploited Vulnerabilities catalog.

    Args:
        source: Which enrichment source to run — "nvd", "epss", "kev", or "all".
    """
    init_db()
    from src.enricher.nvd import enrich_all as nvd_enrich
    from src.enricher.epss import enrich_all as epss_enrich
    from src.enricher.kev import enrich_all as kev_enrich

    sources_run = []
    if source in ("all", "nvd"):
        asyncio.run(nvd_enrich())
        sources_run.append("NVD")
    if source in ("all", "epss"):
        asyncio.run(epss_enrich())
        sources_run.append("EPSS")
    if source in ("all", "kev"):
        asyncio.run(kev_enrich())
        sources_run.append("KEV")

    conn = get_connection()
    enriched = conn.execute(
        "SELECT COUNT(*) as c FROM cves WHERE enriched_at IS NOT NULL"
    ).fetchone()["c"]
    kev_count = conn.execute(
        "SELECT COUNT(*) as c FROM cves WHERE kev_listed = 1"
    ).fetchone()["c"]
    epss_count = conn.execute(
        "SELECT COUNT(*) as c FROM cves WHERE epss_score IS NOT NULL"
    ).fetchone()["c"]
    conn.close()

    return (
        f"Enrichment complete ({', '.join(sources_run)}). "
        f"CVEs enriched from NVD: {enriched}, with EPSS scores: {epss_count}, "
        f"in CISA KEV: {kev_count}."
    )


@tool
def classify_advisories(advisory_id: Optional[str] = None) -> str:
    """Classify advisories using AI to extract attack surface, root cause, and component info.

    Uses Claude to analyze each advisory and extract structured fields:
    affected_component, attack_surface, vulnerability_category,
    root_cause_category, and mitigation_quality.

    Args:
        advisory_id: Optional specific advisory ID to classify (e.g. "SA-0078"). If omitted, classifies all unclassified advisories.
    """
    init_db()
    if advisory_id:
        from src.ai.classifier import classify_advisory
        result = classify_advisory(advisory_id)
        if result:
            return f"Classified {advisory_id}: {json.dumps(result, indent=2)}"
        return f"Could not classify {advisory_id} — advisory not found or classification failed."

    from src.ai.classifier import classify_all
    classify_all()

    conn = get_connection()
    classified = conn.execute("SELECT COUNT(*) as c FROM ai_classifications").fetchone()["c"]
    conn.close()
    return f"Classification complete. {classified} advisories now have AI classifications."


@tool
def query_advisory_db(question: str) -> str:
    """Query the advisory intelligence database to answer questions about advisories, CVEs, patterns, and trends.

    This is the primary tool for answering analytical questions. It queries
    the SQLite database containing advisories, CVEs (with CVSS/EPSS/KEV data),
    AI classifications, and Semgrep rules.

    Args:
        question: A natural language question about the advisory data. Examples: "How many critical CVEs?", "Top CWE patterns", "KEV-listed CVEs", "advisories affecting BGP".
    """
    init_db()
    conn = get_connection()
    results = {}

    q = question.lower()

    if any(w in q for w in ["summary", "overview", "how many", "count", "total", "status"]):
        results["summary"] = {
            "advisories": conn.execute("SELECT COUNT(*) as c FROM advisories").fetchone()["c"],
            "cves": conn.execute("SELECT COUNT(*) as c FROM cves").fetchone()["c"],
            "enriched": conn.execute("SELECT COUNT(*) as c FROM cves WHERE enriched_at IS NOT NULL").fetchone()["c"],
            "classified": conn.execute("SELECT COUNT(*) as c FROM ai_classifications").fetchone()["c"],
            "kev_listed": conn.execute("SELECT COUNT(*) as c FROM cves WHERE kev_listed = 1").fetchone()["c"],
            "semgrep_rules": conn.execute("SELECT COUNT(*) as c FROM semgrep_rules").fetchone()["c"],
        }

    if any(w in q for w in ["cwe", "weakness", "pattern", "recurring", "top"]):
        rows = conn.execute("""
            SELECT cwe_id, cwe_name, COUNT(*) as count, ROUND(AVG(cvss_score), 1) as avg_cvss
            FROM cves WHERE cwe_id IS NOT NULL
            GROUP BY cwe_id ORDER BY count DESC LIMIT 10
        """).fetchall()
        results["top_cwe_patterns"] = [dict(r) for r in rows]

    if any(w in q for w in ["critical", "severe", "high", "severity", "cvss"]):
        rows = conn.execute("""
            SELECT c.cve_id, c.advisory_id, c.cvss_score, c.epss_score, c.kev_listed,
                   c.cwe_id, a.title
            FROM cves c JOIN advisories a ON c.advisory_id = a.id
            WHERE c.cvss_score >= 9.0
            ORDER BY c.cvss_score DESC LIMIT 15
        """).fetchall()
        results["critical_cves"] = [dict(r) for r in rows]

    if any(w in q for w in ["kev", "exploited", "cisa", "actively"]):
        rows = conn.execute("""
            SELECT c.cve_id, c.advisory_id, c.cvss_score, c.epss_score,
                   c.kev_date_added, a.title
            FROM cves c JOIN advisories a ON c.advisory_id = a.id
            WHERE c.kev_listed = 1
            ORDER BY c.kev_date_added DESC
        """).fetchall()
        results["kev_cves"] = [dict(r) for r in rows]

    if any(w in q for w in ["epss", "exploit", "probability", "likely"]):
        rows = conn.execute("""
            SELECT c.cve_id, c.advisory_id, c.cvss_score, c.epss_score,
                   c.epss_percentile, c.kev_listed, a.title
            FROM cves c JOIN advisories a ON c.advisory_id = a.id
            WHERE c.epss_score IS NOT NULL
            ORDER BY c.epss_score DESC LIMIT 15
        """).fetchall()
        results["high_epss_cves"] = [dict(r) for r in rows]

    if any(w in q for w in ["component", "affected", "surface", "attack"]):
        rows = conn.execute("""
            SELECT affected_component, attack_surface, vulnerability_category,
                   root_cause_category, COUNT(*) as count
            FROM ai_classifications
            GROUP BY affected_component, attack_surface
            ORDER BY count DESC LIMIT 15
        """).fetchall()
        results["component_analysis"] = [dict(r) for r in rows]

    if any(w in q for w in ["rule", "semgrep", "sast", "prevention", "coverage"]):
        rows = conn.execute("""
            SELECT rule_id, cwe_id, cwe_name, rationale, generated_at
            FROM semgrep_rules ORDER BY cwe_id
        """).fetchall()
        results["semgrep_rules"] = [dict(r) for r in rows]

    if any(w in q for w in ["trend", "year", "timeline", "history"]):
        rows = conn.execute("""
            SELECT SUBSTR(c.cve_id, 5, 4) as year,
                   COUNT(DISTINCT c.advisory_id) as advisory_count,
                   COUNT(*) as cve_count,
                   ROUND(AVG(c.cvss_score), 1) as avg_cvss
            FROM cves c WHERE c.cvss_score IS NOT NULL
            GROUP BY year ORDER BY year
        """).fetchall()
        results["yearly_trend"] = [dict(r) for r in rows]

    if any(w in q for w in ["advisory", "sa-", "detail", "specific"]):
        import re
        sa_match = re.search(r"SA-?\d{3,4}", question, re.IGNORECASE)
        if sa_match:
            sa_id = sa_match.group(0).upper()
            if not sa_id.startswith("SA-"):
                sa_id = "SA-" + sa_id.lstrip("SA")
            adv = conn.execute("SELECT * FROM advisories WHERE id = ?", (sa_id,)).fetchone()
            if adv:
                cves = conn.execute("SELECT * FROM cves WHERE advisory_id = ?", (sa_id,)).fetchall()
                classifications = conn.execute(
                    "SELECT * FROM ai_classifications WHERE advisory_id = ?", (sa_id,)
                ).fetchall()
                results["advisory_detail"] = {
                    "advisory": dict(adv),
                    "cves": [dict(r) for r in cves],
                    "classifications": [dict(r) for r in classifications],
                }

    if not results:
        results["all_advisories"] = []
        rows = conn.execute("""
            SELECT a.id, a.title, a.published_date,
                   COUNT(c.cve_id) as cve_count, MAX(c.cvss_score) as max_cvss
            FROM advisories a LEFT JOIN cves c ON a.id = c.advisory_id
            GROUP BY a.id ORDER BY a.published_date DESC LIMIT 20
        """).fetchall()
        results["all_advisories"] = [dict(r) for r in rows]

    conn.close()
    return json.dumps(results, indent=2, default=str)


@tool
def analyze_patterns() -> str:
    """Run full pattern analysis on the advisory dataset.

    Produces CWE distribution, severity breakdown, attack surface analysis,
    yearly trends, EPSS vs CVSS correlation, KEV matches, and component heat map.
    Use this for comprehensive trend analysis and program-level insights.
    """
    init_db()
    from src.analyzer.patterns import full_analysis
    analysis = full_analysis()

    summary_parts = []
    cwe_dist = analysis.get("cwe_distribution", [])
    if cwe_dist:
        top3 = ", ".join(f"{c['cwe_id']} ({c['count']}x)" for c in cwe_dist[:3])
        summary_parts.append(f"Top CWEs: {top3}")

    severity = analysis.get("severity_distribution", {})
    if severity:
        summary_parts.append(f"Severity: {json.dumps(severity)}")

    kev = analysis.get("kev_matches", [])
    summary_parts.append(f"KEV-listed CVEs: {len(kev)}")

    trend = analysis.get("yearly_trend", [])
    if trend:
        recent = trend[-1]
        summary_parts.append(
            f"Latest year ({recent['year']}): {recent['cve_count']} CVEs, avg CVSS {recent['avg_cvss']}"
        )

    summary = "\n".join(summary_parts)
    full_json = json.dumps(analysis, indent=2, default=str)
    return f"Pattern Analysis Summary:\n{summary}\n\nFull data:\n{full_json}"


@tool
def generate_insights() -> str:
    """Generate AI-powered program-level insights from the advisory data.

    Uses Claude to analyze patterns across all advisories and produce
    actionable findings with SDLC recommendations for the PSIRT team.
    """
    init_db()
    from src.analyzer.patterns import full_analysis
    from src.ai.classifier import generate_insights as _generate_insights

    analysis = full_analysis()
    insights = _generate_insights(analysis)
    return json.dumps(insights, indent=2, default=str)


@tool
def generate_semgrep_rules(cwe_filter: Optional[str] = None) -> str:
    """Generate Semgrep SAST rules from recurring CWE patterns in the advisory history.

    Analyzes which CWE categories recur most often and generates Semgrep rules
    to catch those patterns in CI. This is the PSIRT-to-SDLC feedback loop.

    Args:
        cwe_filter: Optional CWE ID to generate rules for (e.g. "CWE-78"). If omitted, generates rules for all top recurring CWEs.
    """
    init_db()
    from src.rules.generator import generate_rules, get_rules

    rules = generate_rules()

    if cwe_filter:
        rules = [r for r in rules if r.get("cwe_id") == cwe_filter.upper()]

    if not rules:
        return f"No Semgrep rules generated{f' for {cwe_filter}' if cwe_filter else ''}."

    summary = f"Generated {len(rules)} Semgrep rules:\n"
    for r in rules:
        summary += f"  - {r['rule_id']}: {r['cwe_id']} ({r['cwe_name']}) [{r['severity']}]\n"
        summary += f"    Rationale: {r['rationale']}\n"

    return summary


COMPLIANCEGUARD_ROOT = Path(__file__).parent.parent.parent.parent.parent / "complianceguard"


@tool
def scan_infrastructure(container_name: Optional[str] = None) -> str:
    """Scan live Docker containers for compliance violations using ComplianceGuard.

    Connects to the ComplianceGuard project to scan running containers against
    security policies (privileged mode, capabilities, read-only filesystem,
    no-new-privileges). Use this to cross-reference advisory patterns with
    live infrastructure state — the PSIRT-to-runtime feedback loop.

    Args:
        container_name: Optional specific container to inspect (e.g. "cg-data-processor"). If omitted, scans all managed containers and evaluates compliance.
    """
    import sys
    cg_root = str(COMPLIANCEGUARD_ROOT)
    if cg_root not in sys.path:
        sys.path.insert(0, cg_root)

    old_policy_dir = os.environ.get("POLICY_DIR")
    os.environ["POLICY_DIR"] = str(COMPLIANCEGUARD_ROOT / "policies")

    try:
        from agent.scanner import scan_containers, scan_all
        from agent.evaluator import evaluate_all

        if container_name:
            containers = scan_containers()
            matched = [c for c in containers if container_name.lower() in c["name"].lower()]
            if not matched:
                available = [c["name"] for c in containers]
                return (
                    f"Container '{container_name}' not found. "
                    f"Available managed containers: {', '.join(available)}"
                )
            c = matched[0]
            lines = [
                f"Container: {c['name']}",
                f"Status: {c['status']} (running: {c['running']})",
                f"Image: {c['image']}",
                f"Security config:",
                f"  Privileged: {c['privileged']}",
                f"  Read-only filesystem: {c['read_only']}",
                f"  Capabilities dropped: {c['cap_drop']}",
                f"  Capabilities added: {c['cap_add']}",
                f"  Security options: {c['security_opt']}",
                f"  Network mode: {c['network_mode']}",
                f"  Exposed ports: {c['ports']}",
                f"  Compliance tier: {c['labels'].get('complianceguard.tier', 'unknown')}",
            ]
            return "\n".join(lines)

        observed = scan_all()
        evaluated = evaluate_all(observed)
        summary = evaluated.get("summary", {})
        findings = evaluated.get("findings", [])

        lines = [
            f"ComplianceGuard Infrastructure Scan:",
            f"  Containers scanned: {summary.get('containers_scanned', 0)}",
            f"  Total findings: {summary.get('total_findings', 0)}",
            f"  Critical: {summary.get('critical', 0)}",
            f"  High: {summary.get('high', 0)}",
            f"  Medium: {summary.get('medium', 0)}",
            f"",
        ]

        if findings:
            lines.append("Findings:")
            for f in findings:
                lines.append(
                    f"  [{f['severity']}] {f['container']} — {f['rule_id']}: "
                    f"{f['description']} (expected: {f['declared']}, observed: {f['observed']})"
                )
        else:
            lines.append("All containers are compliant.")

        return "\n".join(lines)

    except ImportError as e:
        return (
            f"ComplianceGuard not available: {e}. "
            f"Ensure the complianceguard project exists at {cg_root}"
        )
    except RuntimeError as e:
        return f"Cannot connect to Docker: {e}. Make sure Docker Desktop is running."
    finally:
        if old_policy_dir is not None:
            os.environ["POLICY_DIR"] = old_policy_dir
        elif "POLICY_DIR" in os.environ:
            del os.environ["POLICY_DIR"]


@tool
def cross_reference_advisory_with_infrastructure(cwe_id: Optional[str] = None) -> str:
    """Cross-reference advisory CWE patterns with live infrastructure compliance state.

    This is the full closed-loop: advisory history reveals which weakness classes
    recur, and this tool checks whether running containers have related compliance
    gaps. Maps CWE categories to ComplianceGuard policy rules.

    Args:
        cwe_id: Optional specific CWE to check (e.g. "CWE-78"). If omitted, checks the top 5 recurring CWEs.
    """
    init_db()

    CWE_TO_COMPLIANCE_RULES = {
        "CWE-78": {
            "name": "OS Command Injection",
            "compliance_rules": ["no-privileged-containers", "drop-all-capabilities"],
            "rationale": "Privileged containers and excessive capabilities amplify command injection impact",
        },
        "CWE-287": {
            "name": "Improper Authentication",
            "compliance_rules": ["no-new-privileges"],
            "rationale": "Privilege escalation after auth bypass is prevented by no-new-privileges",
        },
        "CWE-269": {
            "name": "Improper Privilege Management",
            "compliance_rules": ["no-privileged-containers", "drop-all-capabilities", "no-new-privileges"],
            "rationale": "Direct mapping — privilege management vulnerabilities are mitigated by least-privilege container config",
        },
        "CWE-863": {
            "name": "Incorrect Authorization",
            "compliance_rules": ["no-privileged-containers", "no-new-privileges"],
            "rationale": "Authorization bypass impact is contained by restricting container privileges",
        },
        "CWE-200": {
            "name": "Information Exposure",
            "compliance_rules": ["read-only-root-filesystem"],
            "rationale": "Read-only filesystem prevents attackers from writing exfiltration tools",
        },
        "CWE-532": {
            "name": "Sensitive Info in Logs",
            "compliance_rules": ["read-only-root-filesystem"],
            "rationale": "Read-only filesystem limits where log files with sensitive data can be written",
        },
        "CWE-400": {
            "name": "Uncontrolled Resource Consumption",
            "compliance_rules": ["drop-all-capabilities"],
            "rationale": "Dropping capabilities limits resource access vectors for DoS",
        },
    }

    conn = get_connection()
    if cwe_id:
        cwes_to_check = [{"cwe_id": cwe_id.upper()}]
        row = conn.execute(
            "SELECT COUNT(*) as count, ROUND(AVG(cvss_score), 1) as avg_cvss FROM cves WHERE cwe_id = ?",
            (cwe_id.upper(),)
        ).fetchone()
        if row:
            cwes_to_check[0]["count"] = row["count"]
            cwes_to_check[0]["avg_cvss"] = row["avg_cvss"]
    else:
        cwes_to_check = [dict(r) for r in conn.execute("""
            SELECT cwe_id, COUNT(*) as count, ROUND(AVG(cvss_score), 1) as avg_cvss
            FROM cves WHERE cwe_id IS NOT NULL
            GROUP BY cwe_id ORDER BY count DESC LIMIT 5
        """).fetchall()]
    conn.close()

    infra_result = scan_infrastructure.tool_func()

    lines = [
        "CROSS-REFERENCE: Advisory Patterns vs Infrastructure Compliance",
        "=" * 60,
        "",
    ]

    for cwe in cwes_to_check:
        cid = cwe.get("cwe_id", "")
        mapping = CWE_TO_COMPLIANCE_RULES.get(cid)
        lines.append(f"  {cid} — {mapping['name'] if mapping else 'Unknown'} ({cwe.get('count', '?')}x, avg CVSS {cwe.get('avg_cvss', '?')})")

        if not mapping:
            lines.append(f"    No compliance rule mapping defined for {cid}")
            lines.append("")
            continue

        lines.append(f"    Rationale: {mapping['rationale']}")
        lines.append(f"    Related compliance rules: {', '.join(mapping['compliance_rules'])}")

        for rule_id in mapping["compliance_rules"]:
            if f"— {rule_id}:" in infra_result:
                lines.append(f"    !! FINDING: Infrastructure has violations for '{rule_id}'")
                for infra_line in infra_result.split("\n"):
                    if rule_id in infra_line:
                        lines.append(f"       {infra_line.strip()}")
            else:
                lines.append(f"    OK: No violations for '{rule_id}'")
        lines.append("")

    has_gaps = "FINDING" in "\n".join(lines)
    if has_gaps:
        lines.append("RISK: Advisory patterns AND infrastructure gaps overlap.")
        lines.append("Recommend: Fix compliance violations to reduce attack surface for these CWE categories.")
    else:
        lines.append("No overlap between advisory patterns and infrastructure compliance gaps.")

    return "\n".join(lines)


ALL_TOOLS = [
    scrape_advisories,
    enrich_cves,
    classify_advisories,
    query_advisory_db,
    analyze_patterns,
    generate_insights,
    generate_semgrep_rules,
    scan_infrastructure,
    cross_reference_advisory_with_infrastructure,
]
