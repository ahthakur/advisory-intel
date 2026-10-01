"""Use Claude to classify advisories and generate insights."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import anthropic

from src.ai.budget import BudgetExceeded, RunBudget
from src.db import get_connection

MODEL = "claude-haiku-4-5-20251001"

CLASSIFICATION_PROMPT = """You are a product security analyst. Analyze this Arista EOS security advisory and extract structured information.

Advisory Title: {title}
Advisory ID: {advisory_id}
Description:
{description}

CVEs: {cves}

Extract the following as JSON:
{{
    "affected_component": "The EOS subsystem or feature affected (e.g., 'gNMI/gNPSI telemetry', 'TACACS+ authentication', 'tunnel decapsulation', 'logging subsystem', 'P4Runtime API', 'eAPI', 'CLI', 'BGP', 'SNMP')",
    "attack_surface": "One of: 'management-plane', 'control-plane', 'data-plane', 'local-only', 'unknown'",
    "vulnerability_category": "One of: 'remote-code-execution', 'information-disclosure', 'privilege-escalation', 'denial-of-service', 'authentication-bypass', 'configuration-weakness', 'input-validation', 'other'",
    "root_cause_category": "One of: 'credential-handling', 'input-validation', 'access-control', 'protocol-implementation', 'logging-exposure', 'memory-safety', 'race-condition', 'configuration-default', 'other'",
    "mitigation_quality": "One of: 'upgrade-only', 'config-workaround', 'acl-mitigation', 'feature-disable', 'no-mitigation'"
}}

Return ONLY valid JSON, no explanation."""

INSIGHT_PROMPT = """You are a PSIRT program analyst. Given the following analysis of Arista's security advisory history, generate 3-5 actionable insights for the PSIRT team.

Data:
- Top CWE categories: {cwe_data}
- Severity distribution: {severity_data}
- Attack surface breakdown: {attack_surface_data}
- Component heat map: {component_data}
- Yearly trend: {yearly_data}

For each insight:
1. State the finding (what the data shows)
2. Explain why it matters for PSIRT prioritization
3. Recommend a specific SDLC action (SAST rule, coding guideline, code review focus area)

Be specific to Arista EOS and network operating systems. Reference the actual data.
Format as JSON array of objects with keys: "finding", "impact", "recommendation"."""


def get_client() -> anthropic.Anthropic:
    return anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))


def classify_advisory(advisory_id: str, budget: RunBudget | None = None) -> dict | None:
    """Classify a single advisory using Claude. Raises BudgetExceeded at the cap."""
    budget = budget or RunBudget()
    conn = get_connection()
    adv = conn.execute(
        "SELECT * FROM advisories WHERE id = ?", (advisory_id,)
    ).fetchone()
    cves = conn.execute(
        "SELECT cve_id, cvss_score, cwe_id FROM cves WHERE advisory_id = ?",
        (advisory_id,),
    ).fetchall()
    conn.close()

    if not adv:
        return None

    cve_str = ", ".join(
        f"{r['cve_id']} (CVSS: {r['cvss_score']}, CWE: {r['cwe_id']})"
        for r in cves
    )

    prompt = CLASSIFICATION_PROMPT.format(
        title=adv["title"],
        advisory_id=advisory_id,
        description=(adv["description"] or "")[:3000],
        cves=cve_str or "None listed",
    )
    budget.reserve(MODEL, prompt, 500)
    client = get_client()
    resp = client.messages.create(
        model=MODEL,
        max_tokens=500,
        messages=[{"role": "user", "content": prompt}],
    )
    budget.record(MODEL, resp.usage)

    result = _parse_classification(resp.content[0].text if resp.content else "")
    if result is None:
        print(f"    Unparseable response for {advisory_id}; left unclassified")
        return None

    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    # One row per advisory: reclassifying replaces the old row
    conn.execute("DELETE FROM ai_classifications WHERE advisory_id = ?", (advisory_id,))
    conn.execute(
        """INSERT INTO ai_classifications
           (advisory_id, affected_component, attack_surface, vulnerability_category,
            root_cause_category, mitigation_quality, classified_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            advisory_id,
            result.get("affected_component"),
            result.get("attack_surface"),
            result.get("vulnerability_category"),
            result.get("root_cause_category"),
            result.get("mitigation_quality"),
            now,
        ),
    )
    conn.commit()
    conn.close()
    return result


CLASSIFICATION_FIELDS = (
    "affected_component", "attack_surface", "vulnerability_category",
    "root_cause_category", "mitigation_quality",
)


def _parse_classification(text: str) -> dict | None:
    """Pull the classification object out of a model response.

    Handles code fences, prose around the JSON, a one-element array, and
    list values (joined into one string).
    """
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0]
    try:
        result = json.loads(text)
    except json.JSONDecodeError:
        # Prose around the JSON, or several objects in a row: take the first one
        start = text.find("{")
        if start == -1:
            return None
        try:
            result, _ = json.JSONDecoder().raw_decode(text[start:])
        except json.JSONDecodeError:
            return None
    if isinstance(result, list):
        result = next((r for r in result if isinstance(r, dict)), None)
    if not isinstance(result, dict):
        return None
    for field in CLASSIFICATION_FIELDS:
        value = result.get(field)
        if isinstance(value, list):
            result[field] = ", ".join(str(v) for v in value)
    return result


def classify_all():
    """Classify all unclassified advisories."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT a.id FROM advisories a
        LEFT JOIN ai_classifications c ON a.id = c.advisory_id
        WHERE c.id IS NULL
    """).fetchall()
    conn.close()

    if not rows:
        print("All advisories already classified.")
        return

    budget = RunBudget()
    print(f"Classifying {len(rows)} advisories with Claude (cap ${budget.cap_usd:.2f})...")
    for i, row in enumerate(rows, 1):
        print(f"  [{i}/{len(rows)}] {row['id']}...")
        try:
            classify_advisory(row["id"], budget)
        except BudgetExceeded as e:
            print(f"  Stopping: {e}. {len(rows) - i + 1} advisories left for the next run.")
            break
        except anthropic.BadRequestError as e:
            # Billing and request errors fail every call the same way; don't repeat them
            print(f"  Stopping: {e.message}")
            break
        except Exception as e:
            print(f"    Error: {e}")

    print(f"Classification complete. {budget.summary()}")


def generate_insights(analysis: dict, budget: RunBudget | None = None) -> list[dict]:
    """Generate program-level insights from analysis data."""
    budget = budget or RunBudget()
    prompt = INSIGHT_PROMPT.format(
        cwe_data=json.dumps(analysis.get("cwe_distribution", [])[:10]),
        severity_data=json.dumps(analysis.get("severity_distribution", {})),
        attack_surface_data=json.dumps(analysis.get("attack_surface", {})),
        component_data=json.dumps(analysis.get("component_heatmap", [])[:10]),
        yearly_data=json.dumps(analysis.get("yearly_trend", [])),
    )
    try:
        budget.reserve(MODEL, prompt, 4000)
    except BudgetExceeded as e:
        return [{"finding": str(e), "impact": "", "recommendation": ""}]
    client = get_client()
    resp = client.messages.create(
        model=MODEL,
        max_tokens=4000,
        messages=[{"role": "user", "content": prompt}],
    )
    budget.record(MODEL, resp.usage)

    try:
        text = resp.content[0].text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1].rsplit("```", 1)[0]
        return json.loads(text)
    except (json.JSONDecodeError, IndexError):
        return [{"finding": "Unable to parse insights", "impact": "", "recommendation": ""}]
