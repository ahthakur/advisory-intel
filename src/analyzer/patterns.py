"""Analyze advisory data for CWE patterns, trends, and component heat maps."""

from src.db import get_connection


def cwe_distribution() -> list[dict]:
    """Top CWE categories across all advisories."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT cwe_id, cwe_name, COUNT(*) as count,
               AVG(cvss_score) as avg_cvss,
               GROUP_CONCAT(DISTINCT advisory_id) as advisory_ids
        FROM cves
        WHERE cwe_id IS NOT NULL
        GROUP BY cwe_id
        ORDER BY count DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def severity_distribution() -> dict:
    """Count of CVEs by severity bracket."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT
            CASE
                WHEN cvss_score >= 9.0 THEN 'Critical'
                WHEN cvss_score >= 7.0 THEN 'High'
                WHEN cvss_score >= 4.0 THEN 'Medium'
                WHEN cvss_score > 0 THEN 'Low'
                ELSE 'Unknown'
            END as severity,
            COUNT(*) as count
        FROM cves
        GROUP BY severity
        ORDER BY
            CASE severity
                WHEN 'Critical' THEN 1
                WHEN 'High' THEN 2
                WHEN 'Medium' THEN 3
                WHEN 'Low' THEN 4
                ELSE 5
            END
    """).fetchall()
    conn.close()
    return {r["severity"]: r["count"] for r in rows}


def attack_surface_breakdown() -> list[dict]:
    """Breakdown by CVSS attack vector, complexity, and auth requirements."""
    conn = get_connection()
    vectors = conn.execute("""
        SELECT attack_vector, COUNT(*) as count
        FROM cves WHERE attack_vector IS NOT NULL
        GROUP BY attack_vector ORDER BY count DESC
    """).fetchall()
    complexity = conn.execute("""
        SELECT attack_complexity, COUNT(*) as count
        FROM cves WHERE attack_complexity IS NOT NULL
        GROUP BY attack_complexity ORDER BY count DESC
    """).fetchall()
    privs = conn.execute("""
        SELECT privileges_required, COUNT(*) as count
        FROM cves WHERE privileges_required IS NOT NULL
        GROUP BY privileges_required ORDER BY count DESC
    """).fetchall()
    conn.close()
    return {
        "attack_vector": [dict(r) for r in vectors],
        "attack_complexity": [dict(r) for r in complexity],
        "privileges_required": [dict(r) for r in privs],
    }


def yearly_trend() -> list[dict]:
    """Advisory count by year, with average severity."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT
            SUBSTR(c.cve_id, 5, 4) as year,
            COUNT(DISTINCT c.advisory_id) as advisory_count,
            COUNT(*) as cve_count,
            ROUND(AVG(c.cvss_score), 1) as avg_cvss
        FROM cves c
        WHERE c.cvss_score IS NOT NULL
        GROUP BY year
        ORDER BY year
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def epss_vs_cvss() -> list[dict]:
    """CVEs with both EPSS and CVSS scores for scatter analysis."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT cve_id, advisory_id, cvss_score, epss_score, epss_percentile,
               cwe_id, attack_vector, kev_listed
        FROM cves
        WHERE cvss_score IS NOT NULL AND epss_score IS NOT NULL
        ORDER BY epss_score DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def kev_matches() -> list[dict]:
    """CVEs that appear in CISA KEV."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT c.cve_id, c.advisory_id, c.cvss_score, c.epss_score,
               c.kev_date_added, a.title
        FROM cves c
        JOIN advisories a ON c.advisory_id = a.id
        WHERE c.kev_listed = 1
        ORDER BY c.kev_date_added DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def component_heatmap() -> list[dict]:
    """Advisory count by affected component (from AI classification)."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT affected_component, COUNT(*) as count,
               GROUP_CONCAT(DISTINCT advisory_id) as advisory_ids
        FROM ai_classifications
        WHERE affected_component IS NOT NULL
          AND LOWER(affected_component) != 'unknown'
        GROUP BY affected_component
        ORDER BY count DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def full_analysis() -> dict:
    """Run all analyses and return combined results."""
    return {
        "cwe_distribution": cwe_distribution(),
        "severity_distribution": severity_distribution(),
        "attack_surface": attack_surface_breakdown(),
        "yearly_trend": yearly_trend(),
        "epss_vs_cvss": epss_vs_cvss(),
        "kev_matches": kev_matches(),
        "component_heatmap": component_heatmap(),
    }
