"""Enrich CVEs with NVD data (CVSS vectors, CWE classifications)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx

from src.db import get_connection

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def enrich_cve(client: httpx.AsyncClient, cve_id: str) -> dict | None:
    """Fetch CVE details from NVD API v2."""
    resp = await client.get(NVD_API_URL, params={"cveId": cve_id})
    if resp.status_code == 403:
        await asyncio.sleep(6)
        resp = await client.get(NVD_API_URL, params={"cveId": cve_id})
    if resp.status_code != 200:
        return None

    data = resp.json()
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    cve_data = vulns[0].get("cve", {})
    result = {"cve_id": cve_id}

    metrics = cve_data.get("metrics", {})
    for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(version_key, [])
        if metric_list:
            cvss = metric_list[0].get("cvssData", {})
            result["cvss_score"] = cvss.get("baseScore")
            result["cvss_vector"] = cvss.get("vectorString")
            result["cvss_version"] = cvss.get("version")
            result["attack_vector"] = cvss.get("attackVector")
            result["attack_complexity"] = cvss.get("attackComplexity")
            result["privileges_required"] = cvss.get("privilegesRequired")
            result["user_interaction"] = cvss.get("userInteraction")
            result["scope"] = cvss.get("scope")
            result["confidentiality_impact"] = cvss.get("confidentialityImpact")
            result["integrity_impact"] = cvss.get("integrityImpact")
            result["availability_impact"] = cvss.get("availabilityImpact")
            break

    weaknesses = cve_data.get("weaknesses", [])
    for w in weaknesses:
        for desc in w.get("description", []):
            cwe_val = desc.get("value", "")
            if cwe_val.startswith("CWE-"):
                result["cwe_id"] = cwe_val
                break

    descriptions = cve_data.get("descriptions", [])
    for d in descriptions:
        if d.get("lang") == "en":
            result["nvd_description"] = d.get("value", "")[:2000]
            break

    return result


def save_enrichment(enrichment: dict):
    """Update CVE record with NVD enrichment data."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """UPDATE cves SET
           cvss_score=?, cvss_vector=?, cvss_version=?,
           cwe_id=?, attack_vector=?, attack_complexity=?,
           privileges_required=?, user_interaction=?, scope=?,
           confidentiality_impact=?, integrity_impact=?, availability_impact=?,
           nvd_description=?, enriched_at=?
           WHERE cve_id=?""",
        (
            enrichment.get("cvss_score"),
            enrichment.get("cvss_vector"),
            enrichment.get("cvss_version"),
            enrichment.get("cwe_id"),
            enrichment.get("attack_vector"),
            enrichment.get("attack_complexity"),
            enrichment.get("privileges_required"),
            enrichment.get("user_interaction"),
            enrichment.get("scope"),
            enrichment.get("confidentiality_impact"),
            enrichment.get("integrity_impact"),
            enrichment.get("availability_impact"),
            enrichment.get("nvd_description"),
            now,
            enrichment["cve_id"],
        ),
    )
    conn.commit()
    conn.close()


async def enrich_all():
    """Enrich all unenriched CVEs from NVD."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT cve_id FROM cves WHERE enriched_at IS NULL"
    ).fetchall()
    conn.close()

    if not rows:
        print("All CVEs already enriched.")
        return

    print(f"Enriching {len(rows)} CVEs from NVD...")

    async with httpx.AsyncClient(
        timeout=30.0,
        headers={"User-Agent": "advisory-intel/1.0 (security-research)"},
    ) as client:
        not_found = 0
        for i, row in enumerate(rows, 1):
            cve_id = row["cve_id"]
            print(f"  [{i}/{len(rows)}] {cve_id}...", end="", flush=True)
            try:
                enrichment = await enrich_cve(client, cve_id)
                if enrichment:
                    save_enrichment(enrichment)
                    cwe = enrichment.get("cwe_id", "")
                    score = enrichment.get("cvss_score", "")
                    print(f" CVSS:{score} {cwe}")
                else:
                    not_found += 1
                    print(f" not in NVD")
            except Exception as e:
                print(f" error: {e}")
            await asyncio.sleep(6.5)

    print(f"NVD enrichment complete. {not_found} CVEs not found in NVD.")
