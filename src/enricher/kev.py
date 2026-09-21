"""Enrich CVEs with CISA Known Exploited Vulnerabilities (KEV) catalog data."""

from datetime import datetime, timezone

import httpx

from src.db import get_connection

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_URL_ALT = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"


async def enrich_all():
    """Check all CVEs against the CISA KEV catalog."""
    conn = get_connection()
    rows = conn.execute("SELECT cve_id FROM cves").fetchall()
    conn.close()

    if not rows:
        print("No CVEs to check against KEV.")
        return

    cve_ids = {r["cve_id"] for r in rows}
    print(f"Checking {len(cve_ids)} CVEs against CISA KEV catalog...")

    async with httpx.AsyncClient(
        timeout=30.0,
        headers={"User-Agent": "advisory-intel/1.0 (security-research)"},
    ) as client:
        resp = await client.get(KEV_URL)
        if resp.status_code != 200:
            print(f"  Primary KEV URL returned {resp.status_code}, trying GitHub mirror...")
            resp = await client.get(KEV_URL_ALT)
        if resp.status_code != 200:
            print(f"  KEV catalog unavailable (status {resp.status_code})")
            return
        kev_data = resp.json()

    kev_lookup = {}
    for vuln in kev_data.get("vulnerabilities", []):
        kev_lookup[vuln["cveID"]] = vuln.get("dateAdded")

    matched = 0
    conn = get_connection()
    for cve_id in cve_ids:
        if cve_id in kev_lookup:
            conn.execute(
                "UPDATE cves SET kev_listed=1, kev_date_added=? WHERE cve_id=?",
                (kev_lookup[cve_id], cve_id),
            )
            matched += 1
    conn.commit()
    conn.close()

    print(f"KEV enrichment complete. {matched} CVEs found in KEV catalog.")
