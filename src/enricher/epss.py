"""Enrich CVEs with EPSS (Exploit Prediction Scoring System) data."""

from datetime import datetime, timezone

import httpx

from src.db import get_connection

EPSS_API_URL = "https://api.first.org/data/v1/epss"


async def fetch_epss_scores(client: httpx.AsyncClient, cve_ids: list[str]) -> dict:
    """Fetch EPSS scores for a batch of CVE IDs."""
    batch = ",".join(cve_ids)
    resp = await client.get(EPSS_API_URL, params={"cve": batch})
    resp.raise_for_status()
    data = resp.json()

    scores = {}
    for entry in data.get("data", []):
        scores[entry["cve"]] = {
            "epss_score": float(entry.get("epss", 0)),
            "epss_percentile": float(entry.get("percentile", 0)),
        }
    return scores


async def enrich_all():
    """Fetch EPSS scores for all CVEs."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT cve_id FROM cves WHERE epss_score IS NULL"
    ).fetchall()
    conn.close()

    if not rows:
        print("All CVEs already have EPSS scores.")
        return

    cve_ids = [r["cve_id"] for r in rows]
    print(f"Fetching EPSS scores for {len(cve_ids)} CVEs...")

    async with httpx.AsyncClient(
        timeout=30.0,
        headers={"User-Agent": "advisory-intel/1.0 (security-research)"},
    ) as client:
        batch_size = 100
        for start in range(0, len(cve_ids), batch_size):
            batch = cve_ids[start : start + batch_size]
            try:
                scores = await fetch_epss_scores(client, batch)
                conn = get_connection()
                now = datetime.now(timezone.utc).isoformat()
                for cve_id, data in scores.items():
                    conn.execute(
                        "UPDATE cves SET epss_score=?, epss_percentile=? WHERE cve_id=?",
                        (data["epss_score"], data["epss_percentile"], cve_id),
                    )
                conn.commit()
                conn.close()
                print(f"  Updated {len(scores)} scores (batch {start // batch_size + 1})")
            except Exception as e:
                print(f"  Error fetching EPSS batch: {e}")

    print("EPSS enrichment complete.")
