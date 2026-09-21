"""Generate Semgrep rules from recurring CWE patterns in advisory data.

This is the PSIRT-to-SDLC feedback loop: advisory history reveals which weakness
classes keep recurring, and this module turns those patterns into prevention
rules that SAST can enforce before code ships.
"""

from __future__ import annotations

import yaml
from datetime import datetime, timezone

from src.db import get_connection

CWE_RULES = {
    "CWE-78": {
        "name": "OS Command Injection",
        "rules": [
            {
                "rule_id": "arista-cwe78-os-system-call",
                "pattern": "os.system(...)",
                "message": "Direct os.system() call detected. Use subprocess.run() with shell=False and a list of arguments to prevent command injection (CWE-78). Arista advisory history shows 11 command injection findings — this is the #1 recurring weakness.",
                "severity": "ERROR",
                "languages": ["python"],
                "metadata_cwe": "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
            },
            {
                "rule_id": "arista-cwe78-subprocess-shell",
                "pattern": "subprocess.call($CMD, shell=True, ...)",
                "patterns_list": [
                    {"pattern": "subprocess.$FUNC(..., shell=True, ...)"},
                    {"metavariable-regex": {"metavariable": "$FUNC", "regex": "(call|run|Popen|check_output|check_call)"}},
                ],
                "message": "subprocess with shell=True passes input through the shell, enabling command injection (CWE-78). Use shell=False with a list of arguments.",
                "severity": "ERROR",
                "languages": ["python"],
                "metadata_cwe": "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
            },
            {
                "rule_id": "arista-cwe78-eval-exec",
                "pattern": "eval(...)",
                "patterns_list": [
                    {"pattern-either": [
                        {"pattern": "eval(...)"},
                        {"pattern": "exec(...)"},
                    ]},
                ],
                "message": "eval()/exec() with dynamic input enables code injection. Use safe alternatives like ast.literal_eval() for data parsing (CWE-78).",
                "severity": "WARNING",
                "languages": ["python"],
                "metadata_cwe": "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
            },
        ],
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "rules": [
            {
                "rule_id": "arista-cwe287-hardcoded-password",
                "patterns_list": [
                    {"pattern-either": [
                        {"pattern": "$X = \"...\""},
                        {"pattern": "$X = '...'"},
                    ]},
                    {"metavariable-regex": {"metavariable": "$X", "regex": ".*(password|passwd|secret|token|api_key|apikey|auth_token).*"}},
                ],
                "message": "Potential hardcoded credential detected. Credentials must be loaded from secure storage, not embedded in source (CWE-287). Arista has 10 authentication-related advisories.",
                "severity": "ERROR",
                "languages": ["python"],
                "metadata_cwe": "CWE-287: Improper Authentication",
            },
            {
                "rule_id": "arista-cwe287-no-auth-check",
                "patterns_list": [
                    {"pattern": """
def $HANDLER(request, ...):
    ...
    $RESPONSE
"""},
                    {"pattern-not": """
def $HANDLER(request, ...):
    ...
    authenticate(...)
    ...
"""},
                    {"metavariable-regex": {"metavariable": "$HANDLER", "regex": ".*(api_|handle_|rpc_|grpc_).*"}},
                ],
                "message": "API/RPC handler without authentication check. All network-facing handlers must verify caller identity before processing (CWE-287).",
                "severity": "WARNING",
                "languages": ["python"],
                "metadata_cwe": "CWE-287: Improper Authentication",
            },
        ],
    },
    "CWE-532": {
        "name": "Insertion of Sensitive Information into Log File",
        "rules": [
            {
                "rule_id": "arista-cwe532-log-password",
                "patterns_list": [
                    {"pattern-either": [
                        {"pattern": "logging.$LEVEL(... + $SECRET + ...)"},
                        {"pattern": "logging.$LEVEL(f\"...{$SECRET}...\")"},
                        {"pattern": "print(... + $SECRET + ...)"},
                    ]},
                    {"metavariable-regex": {"metavariable": "$SECRET", "regex": ".*(password|secret|token|key|credential|api_key|private).*"}},
                ],
                "message": "Sensitive data logged in plaintext. Credentials, tokens, and keys must be redacted before logging (CWE-532). Arista has 8 advisories for information exposure via logs.",
                "severity": "ERROR",
                "languages": ["python"],
                "metadata_cwe": "CWE-532: Insertion of Sensitive Information into Log File",
            },
        ],
    },
    "CWE-863": {
        "name": "Incorrect Authorization",
        "rules": [
            {
                "rule_id": "arista-cwe863-role-string-compare",
                "patterns_list": [
                    {"pattern-either": [
                        {"pattern": "if $USER.role == \"admin\": ..."},
                        {"pattern": "if $USER.role != \"admin\": ..."},
                        {"pattern": "if role == \"admin\": ..."},
                    ]},
                ],
                "message": "Authorization via string comparison is fragile. Use a centralized RBAC framework with privilege level checks, not role name strings (CWE-863). Arista has 6 authorization bypass advisories.",
                "severity": "WARNING",
                "languages": ["python"],
                "metadata_cwe": "CWE-863: Incorrect Authorization",
            },
        ],
    },
    "CWE-400": {
        "name": "Uncontrolled Resource Consumption",
        "rules": [
            {
                "rule_id": "arista-cwe400-unbounded-read",
                "patterns_list": [
                    {"pattern-either": [
                        {"pattern": "$FD.read()"},
                        {"pattern": "request.body"},
                    ]},
                ],
                "message": "Unbounded read without size limit. Network-facing input must specify max size to prevent resource exhaustion (CWE-400). 5 Arista advisories trace to uncontrolled resource consumption.",
                "severity": "WARNING",
                "languages": ["python"],
                "metadata_cwe": "CWE-400: Uncontrolled Resource Consumption",
            },
        ],
    },
    "CWE-200": {
        "name": "Exposure of Sensitive Information",
        "rules": [
            {
                "rule_id": "arista-cwe200-stack-trace-response",
                "patterns_list": [
                    {"pattern-either": [
                        {"pattern": "traceback.format_exc(...)"},
                        {"pattern": "traceback.print_exc(...)"},
                    ]},
                ],
                "message": "Stack traces can expose internal paths, versions, and architecture to attackers. Return generic error messages to clients and log details server-side only (CWE-200).",
                "severity": "WARNING",
                "languages": ["python"],
                "metadata_cwe": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
            },
        ],
    },
}


def _build_rule_yaml(rule_def: dict) -> str:
    """Build a valid Semgrep YAML rule from a rule definition."""
    rule = {
        "id": rule_def["rule_id"],
        "message": rule_def["message"],
        "severity": rule_def["severity"],
        "languages": rule_def["languages"],
        "metadata": {
            "cwe": rule_def["metadata_cwe"],
            "source": "advisory-intel (derived from Arista PSIRT advisory patterns)",
            "confidence": "MEDIUM",
        },
    }

    if "patterns_list" in rule_def:
        rule["patterns"] = rule_def["patterns_list"]
    elif "pattern" in rule_def:
        rule["pattern"] = rule_def["pattern"]

    doc = {"rules": [rule]}
    return yaml.dump(doc, default_flow_style=False, sort_keys=False, width=120)


def generate_rules() -> list[dict]:
    """Generate Semgrep rules for the top recurring CWEs in the advisory data."""
    conn = get_connection()
    top_cwes = conn.execute("""
        SELECT cwe_id, COUNT(*) as count, AVG(cvss_score) as avg_cvss
        FROM cves
        WHERE cwe_id IS NOT NULL
        GROUP BY cwe_id
        ORDER BY count DESC
        LIMIT 15
    """).fetchall()
    conn.close()

    generated = []
    now = datetime.now(timezone.utc).isoformat()

    conn = get_connection()
    conn.execute("DELETE FROM semgrep_rules")

    for row in top_cwes:
        cwe_id = row["cwe_id"]
        if cwe_id not in CWE_RULES:
            continue

        cwe_def = CWE_RULES[cwe_id]
        for rule_def in cwe_def["rules"]:
            rule_yaml = _build_rule_yaml(rule_def)
            rationale = (
                f"Generated from {row['count']} occurrences of {cwe_id} "
                f"({cwe_def['name']}) in Arista advisory history. "
                f"Avg CVSS: {row['avg_cvss']:.1f}."
            )

            conn.execute(
                """INSERT INTO semgrep_rules
                   (cwe_id, cwe_name, rule_id, rule_yaml, rationale, generated_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (cwe_id, cwe_def["name"], rule_def["rule_id"],
                 rule_yaml, rationale, now),
            )

            generated.append({
                "cwe_id": cwe_id,
                "cwe_name": cwe_def["name"],
                "rule_id": rule_def["rule_id"],
                "rule_yaml": rule_yaml,
                "rationale": rationale,
                "severity": rule_def["severity"],
            })

    conn.commit()
    conn.close()

    print(f"Generated {len(generated)} Semgrep rules from advisory patterns.")
    return generated


def get_rules() -> list[dict]:
    """Fetch all stored Semgrep rules."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM semgrep_rules ORDER BY cwe_id, rule_id"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def export_rules_file() -> str:
    """Export all rules as a single Semgrep YAML file."""
    conn = get_connection()
    rows = conn.execute("SELECT rule_yaml FROM semgrep_rules").fetchall()
    conn.close()

    all_rules = []
    for row in rows:
        parsed = yaml.safe_load(row["rule_yaml"])
        if parsed and "rules" in parsed:
            all_rules.extend(parsed["rules"])

    doc = {"rules": all_rules}
    return yaml.dump(doc, default_flow_style=False, sort_keys=False, width=120)
