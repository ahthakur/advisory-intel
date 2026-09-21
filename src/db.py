import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "advisory_intel.db"


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS advisories (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            url TEXT NOT NULL,
            published_date TEXT,
            last_updated TEXT,
            severity TEXT,
            description TEXT,
            affected_products TEXT,
            affected_versions TEXT,
            fixed_versions TEXT,
            workaround TEXT,
            raw_html TEXT,
            scraped_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            advisory_id TEXT NOT NULL,
            cvss_score REAL,
            cvss_vector TEXT,
            cvss_version TEXT,
            cwe_id TEXT,
            cwe_name TEXT,
            attack_vector TEXT,
            attack_complexity TEXT,
            privileges_required TEXT,
            user_interaction TEXT,
            scope TEXT,
            confidentiality_impact TEXT,
            integrity_impact TEXT,
            availability_impact TEXT,
            epss_score REAL,
            epss_percentile REAL,
            kev_listed INTEGER DEFAULT 0,
            kev_date_added TEXT,
            nvd_description TEXT,
            enriched_at TEXT,
            FOREIGN KEY (advisory_id) REFERENCES advisories(id)
        );

        CREATE TABLE IF NOT EXISTS ai_classifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            advisory_id TEXT NOT NULL,
            affected_component TEXT,
            attack_surface TEXT,
            vulnerability_category TEXT,
            root_cause_category TEXT,
            mitigation_quality TEXT,
            insight TEXT,
            classified_at TEXT NOT NULL,
            FOREIGN KEY (advisory_id) REFERENCES advisories(id)
        );

        CREATE TABLE IF NOT EXISTS semgrep_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cwe_id TEXT NOT NULL,
            cwe_name TEXT,
            rule_id TEXT NOT NULL,
            rule_yaml TEXT NOT NULL,
            rationale TEXT,
            generated_at TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()
