"""Scrapes security advisories from Arista's CSAF JSON feed and advisory pages.

Two data sources:
1. CSAF JSON files — structured, machine-readable (no bot protection)
2. Main advisory list — richer summaries, covers advisories without CSAF

CSAF link extraction and advisory list scraping require Playwright (via MCP)
to bypass bot protection. The scraper stores extracted links as JSON in data/
so subsequent runs can work from cached link files without a browser.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx

from src.db import get_connection

DATA_DIR = Path(__file__).parent.parent.parent / "data"
CSAF_LINKS_FILE = DATA_DIR / "csaf_links.json"
ADVISORY_LIST_FILE = DATA_DIR / "advisory_list.json"


async def fetch_csaf_json(client: httpx.AsyncClient, url: str) -> dict | None:
    """Download and parse a CSAF JSON file (no bot protection on these)."""
    try:
        resp = await client.get(url)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


def parse_csaf_data(csaf: dict) -> dict:
    """Extract structured fields from a CSAF JSON document."""
    result = {"cves": [], "products": [], "description": "", "published_date": ""}

    tracking = csaf.get("document", {}).get("tracking", {})
    result["published_date"] = tracking.get("initial_release_date", "")

    for branch in csaf.get("product_tree", {}).get("branches", []):
        _extract_products(branch, result["products"])

    notes = csaf.get("document", {}).get("notes", [])
    for note in notes:
        if note.get("category") in ("summary", "description"):
            result["description"] = note.get("text", "")[:5000]
            break

    for vuln in csaf.get("vulnerabilities", []):
        cve_entry = {
            "cve_id": vuln.get("cve", ""),
            "description": "",
            "cvss_score": None,
            "cvss_vector": None,
            "cwe_id": None,
        }

        for note in vuln.get("notes", []):
            if note.get("category") == "description":
                cve_entry["description"] = note.get("text", "")[:2000]

        for score in vuln.get("scores", []):
            cvss_v3 = score.get("cvss_v3")
            if cvss_v3:
                cve_entry["cvss_score"] = cvss_v3.get("baseScore")
                cve_entry["cvss_vector"] = cvss_v3.get("vectorString")

        cwe = vuln.get("cwe")
        if isinstance(cwe, dict) and cwe.get("id"):
            cve_entry["cwe_id"] = cwe["id"]

        if cve_entry["cve_id"]:
            result["cves"].append(cve_entry)

    return result


def _extract_products(branch: dict, products: list):
    """Recursively extract product names from product tree branches."""
    if branch.get("category") == "product_version":
        products.append(branch.get("name", ""))
    for child in branch.get("branches", []):
        _extract_products(child, products)


def save_advisory(advisory_id: str, title: str, url: str, detail: dict):
    """Persist an advisory and its CVEs to the database."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """INSERT OR REPLACE INTO advisories
           (id, title, url, published_date, description,
            affected_products, scraped_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            advisory_id,
            title,
            url,
            detail.get("published_date", ""),
            detail.get("description", ""),
            ", ".join(detail.get("products", [])),
            now,
        ),
    )

    for cve in detail.get("cves", []):
        if not cve.get("cve_id"):
            continue
        conn.execute(
            """INSERT OR IGNORE INTO cves (cve_id, advisory_id, cvss_score, cvss_vector, cwe_id)
               VALUES (?, ?, ?, ?, ?)""",
            (cve["cve_id"], advisory_id, cve.get("cvss_score"),
             cve.get("cvss_vector"), cve.get("cwe_id")),
        )

    conn.commit()
    conn.close()


def save_advisory_from_summary(advisory: dict):
    """Save an advisory from the main list page summary."""
    conn = get_connection()
    exists = conn.execute(
        "SELECT 1 FROM advisories WHERE id = ?", (advisory["id"],)
    ).fetchone()

    if exists:
        if advisory.get("summary"):
            conn.execute(
                "UPDATE advisories SET description = COALESCE(NULLIF(description, ''), ?) WHERE id = ?",
                (advisory["summary"], advisory["id"]),
            )
        conn.commit()
        conn.close()
        return

    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO advisories (id, title, url, published_date, description, scraped_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (advisory["id"], advisory["title"], advisory.get("url", ""),
         advisory.get("date", ""), advisory.get("summary", ""), now),
    )

    cve_ids = re.findall(r"CVE-\d{4}-\d{4,}", advisory.get("summary", ""))
    for cve_id in set(cve_ids):
        conn.execute(
            "INSERT OR IGNORE INTO cves (cve_id, advisory_id) VALUES (?, ?)",
            (cve_id, advisory["id"]),
        )

    conn.commit()
    conn.close()


def _parse_sa_number(title: str) -> str | None:
    """Extract SA number from title like 'Security Advisory 0182'."""
    match = re.search(r"Advisory\s+(\d+)", title)
    return match.group(1) if match else None


async def scrape_all():
    """Main entry point. Uses cached link files from data/ directory."""
    print("=== Advisory Intel Scraper ===\n")

    # Phase 1: CSAF JSON files
    if CSAF_LINKS_FILE.exists():
        with open(CSAF_LINKS_FILE) as f:
            raw = json.load(f)
            csaf_links = json.loads(raw) if isinstance(raw, str) else raw

        print(f"Phase 1: Downloading {len(csaf_links)} CSAF JSON files...")
        async with httpx.AsyncClient(
            timeout=30.0,
            headers={"User-Agent": "advisory-intel/1.0 (security-research)"},
        ) as client:
            for i, link in enumerate(csaf_links, 1):
                sa_num = _parse_sa_number(link["title"])
                if not sa_num:
                    continue
                advisory_id = f"SA-{sa_num.zfill(4)}"

                conn = get_connection()
                exists = conn.execute(
                    "SELECT 1 FROM advisories WHERE id = ?", (advisory_id,)
                ).fetchone()
                conn.close()

                if exists:
                    continue

                print(f"  [{i}/{len(csaf_links)}] {advisory_id}...")
                csaf_data = await fetch_csaf_json(client, link["url"])
                if csaf_data:
                    parsed = parse_csaf_data(csaf_data)
                    save_advisory(advisory_id, link["title"], link["url"], parsed)
                    print(f"    {len(parsed['cves'])} CVEs")
                else:
                    print(f"    Failed to fetch")
    else:
        print("Phase 1: No CSAF links file found (data/csaf_links.json)")
        print("  Run Playwright extraction first — see README")

    # Phase 2: Main advisory list summaries
    if ADVISORY_LIST_FILE.exists():
        with open(ADVISORY_LIST_FILE) as f:
            raw = json.load(f)
            pages = json.loads(raw) if isinstance(raw, str) else raw

        all_advisories = pages if isinstance(pages, list) else pages.get("advisories", [])
        print(f"\nPhase 2: Processing {len(all_advisories)} advisory summaries...")

        new_count = 0
        for adv in all_advisories:
            sa_num = _parse_sa_number(adv["title"])
            if not sa_num:
                continue
            adv["id"] = f"SA-{sa_num.zfill(4)}"

            conn = get_connection()
            exists = conn.execute(
                "SELECT 1 FROM advisories WHERE id = ?", (adv["id"],)
            ).fetchone()
            conn.close()

            if not exists:
                save_advisory_from_summary(adv)
                new_count += 1
            else:
                save_advisory_from_summary(adv)

        print(f"  {new_count} new advisories saved")
    else:
        print("\nPhase 2: No advisory list file found (data/advisory_list.json)")
        print("  Run Playwright extraction first — see README")

    # Summary
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) as c FROM advisories").fetchone()["c"]
    cve_count = conn.execute("SELECT COUNT(*) as c FROM cves").fetchone()["c"]
    conn.close()
    print(f"\n=== Done: {total} advisories, {cve_count} CVEs in database ===")
