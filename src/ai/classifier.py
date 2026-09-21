"""Use Claude to classify advisories and generate insights."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import anthropic

from src.db import get_connection

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


def classify_advisory(advisory_id: str) -> dict | None:
    """Classify a single advisory using Claude."""
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

    client = get_client()
    resp = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=500,
        messages=[
            {
                "role": "user",
                "content": CLASSIFICATION_PROMPT.format(
                    title=adv["title"],
                    advisory_id=advisory_id,
                    description=(adv["description"] or "")[:3000],
                    cves=cve_str or "None listed",
                ),
            }
        ],
    )

    try:
        text = resp.content[0].text
        text = text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1].rsplit("```", 1)[0]
        result = json.loads(text)
    except (json.JSONDecodeError, IndexError):
        return None

    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
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

    print(f"Classifying {len(rows)} advisories with Claude...")
    for i, row in enumerate(rows, 1):
        print(f"  [{i}/{len(rows)}] {row['id']}...")
        try:
            classify_advisory(row["id"])
        except Exception as e:
            print(f"    Error: {e}")

    print("Classification complete.")


def generate_insights(analysis: dict) -> list[dict]:
    """Generate program-level insights from analysis data."""
    client = get_client()
    resp = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=4000,
        messages=[
            {
                "role": "user",
                "content": INSIGHT_PROMPT.format(
                    cwe_data=json.dumps(analysis.get("cwe_distribution", [])[:10]),
                    severity_data=json.dumps(analysis.get("severity_distribution", {})),
                    attack_surface_data=json.dumps(analysis.get("attack_surface", {})),
                    component_data=json.dumps(analysis.get("component_heatmap", [])[:10]),
                    yearly_data=json.dumps(analysis.get("yearly_trend", [])),
                ),
            }
        ],
    )

    try:
        text = resp.content[0].text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1].rsplit("```", 1)[0]
        return json.loads(text)
    except (json.JSONDecodeError, IndexError):
        return [{"finding": "Unable to parse insights", "impact": "", "recommendation": ""}]
