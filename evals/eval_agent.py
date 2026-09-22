"""Evals for the Advisory Intel agent.

Tests that the agent selects the right tools, returns accurate data,
resists hallucination, and handles multi-step reasoning correctly.

Usage:
    export ANTHROPIC_API_KEY=your-key
    cd advisory-intel
    python -m evals.eval_agent           # Run all evals
    python -m evals.eval_agent --quick    # Run tool selection evals only (no LLM calls)
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field

from src.db import init_db, get_connection


@dataclass
class EvalResult:
    name: str
    passed: bool
    details: str
    duration: float = 0.0
    category: str = ""


@dataclass
class EvalSuite:
    results: list[EvalResult] = field(default_factory=list)

    def add(self, result: EvalResult):
        self.results.append(result)

    def summary(self) -> str:
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed

        lines = [
            "",
            "=" * 60,
            f"  EVAL RESULTS: {passed}/{total} passed, {failed} failed",
            "=" * 60,
        ]

        by_category: dict[str, list[EvalResult]] = {}
        for r in self.results:
            by_category.setdefault(r.category, []).append(r)

        for category, results in by_category.items():
            cat_passed = sum(1 for r in results if r.passed)
            lines.append(f"\n  {category} ({cat_passed}/{len(results)})")
            for r in results:
                icon = "PASS" if r.passed else "FAIL"
                lines.append(f"    [{icon}] {r.name} ({r.duration:.1f}s)")
                if not r.passed:
                    lines.append(f"           {r.details}")

        lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Category 1: Tool Selection — does the agent pick the right tool?
# ---------------------------------------------------------------------------

TOOL_SELECTION_CASES = [
    {
        "query": "How many advisories are in the database?",
        "expected_tool": "query_advisory_db",
        "not_expected": ["scrape_advisories", "enrich_cves", "classify_advisories"],
        "reason": "Simple count question should query the DB, not trigger pipeline stages",
    },
    {
        "query": "What are the top recurring CWE patterns?",
        "expected_tool": "query_advisory_db",
        "not_expected": ["scrape_advisories"],
        "reason": "Pattern question should query existing data",
    },
    {
        "query": "Scrape the latest advisories from Arista",
        "expected_tool": "scrape_advisories",
        "not_expected": ["generate_semgrep_rules"],
        "reason": "Explicit scrape request should call the scraper",
    },
    {
        "query": "Generate Semgrep rules for CWE-78",
        "expected_tool": "generate_semgrep_rules",
        "not_expected": ["scrape_advisories", "enrich_cves"],
        "reason": "Explicit rule generation request",
    },
    {
        "query": "Which CVEs are in the CISA KEV catalog?",
        "expected_tool": "query_advisory_db",
        "not_expected": ["scrape_advisories", "generate_semgrep_rules"],
        "reason": "KEV query should search existing data",
    },
    {
        "query": "Classify advisory SA-0078",
        "expected_tool": "classify_advisories",
        "not_expected": ["scrape_advisories", "generate_semgrep_rules"],
        "reason": "Explicit classification request for a specific advisory",
    },
    {
        "query": "What is the yearly trend in advisory severity?",
        "expected_tool": "query_advisory_db",
        "not_expected": ["scrape_advisories", "classify_advisories"],
        "reason": "Trend question should query historical data",
    },
    {
        "query": "Run the full pattern analysis",
        "expected_tool": "analyze_patterns",
        "not_expected": ["scrape_advisories"],
        "reason": "Explicit analysis request should call the analyzer",
    },
]


def eval_tool_selection(agent) -> list[EvalResult]:
    """Test that the agent selects the correct tool for each query."""
    results = []

    for case in TOOL_SELECTION_CASES:
        start = time.time()
        try:
            msg_count_before = len(agent.messages) if hasattr(agent, 'messages') else 0
            response = agent(case["query"])
            elapsed = time.time() - start

            # Check which tools were called in THIS query only
            tool_calls = []
            if hasattr(agent, 'messages') and agent.messages:
                for msg in agent.messages[msg_count_before:]:
                    if isinstance(msg, dict) and msg.get("role") == "assistant":
                        for content in msg.get("content", []):
                            if isinstance(content, dict):
                                # Strands format: {"toolUse": {"name": "...", ...}}
                                tool_use = content.get("toolUse")
                                if tool_use and isinstance(tool_use, dict):
                                    tool_calls.append(tool_use["name"])
                                # Standard Anthropic format fallback
                                elif content.get("type") == "tool_use":
                                    tool_calls.append(content["name"])

            expected = case["expected_tool"]
            called_expected = expected in tool_calls

            # Check no forbidden tools were called
            forbidden_called = [t for t in case.get("not_expected", []) if t in tool_calls]

            passed = called_expected and not forbidden_called

            if not passed:
                detail = f"Expected: {expected}, Called: {tool_calls}, Forbidden called: {forbidden_called}"
            else:
                detail = f"Correctly called {expected}"

            results.append(EvalResult(
                name=f"Tool select: {case['query'][:50]}",
                passed=passed,
                details=detail,
                duration=elapsed,
                category="Tool Selection",
            ))
        except Exception as e:
            results.append(EvalResult(
                name=f"Tool select: {case['query'][:50]}",
                passed=False,
                details=f"Exception: {e}",
                duration=time.time() - start,
                category="Tool Selection",
            ))

    return results


# ---------------------------------------------------------------------------
# Category 2: Data Accuracy — does the agent return real data?
# ---------------------------------------------------------------------------

def eval_data_accuracy(agent) -> list[EvalResult]:
    """Test that the agent returns accurate data from the database."""
    results = []

    conn = get_connection()
    actual_advisory_count = conn.execute("SELECT COUNT(*) as c FROM advisories").fetchone()["c"]
    actual_cve_count = conn.execute("SELECT COUNT(*) as c FROM cves").fetchone()["c"]
    actual_kev_count = conn.execute("SELECT COUNT(*) as c FROM cves WHERE kev_listed = 1").fetchone()["c"]
    conn.close()

    # Test 1: Advisory count accuracy
    start = time.time()
    try:
        response = agent("How many advisories and CVEs are in the database? Give me the exact numbers.")
        resp_text = str(response)
        passed = str(actual_advisory_count) in resp_text and str(actual_cve_count) in resp_text
        results.append(EvalResult(
            name="Accurate advisory/CVE count",
            passed=passed,
            details=f"Expected {actual_advisory_count} advisories, {actual_cve_count} CVEs in response",
            duration=time.time() - start,
            category="Data Accuracy",
        ))
    except Exception as e:
        results.append(EvalResult(
            name="Accurate advisory/CVE count",
            passed=False,
            details=f"Exception: {e}",
            duration=time.time() - start,
            category="Data Accuracy",
        ))

    # Test 2: KEV count accuracy
    start = time.time()
    try:
        response = agent("How many CVEs are in the CISA Known Exploited Vulnerabilities catalog?")
        resp_text = str(response)
        passed = str(actual_kev_count) in resp_text
        results.append(EvalResult(
            name="Accurate KEV count",
            passed=passed,
            details=f"Expected {actual_kev_count} KEV CVEs in response",
            duration=time.time() - start,
            category="Data Accuracy",
        ))
    except Exception as e:
        results.append(EvalResult(
            name="Accurate KEV count",
            passed=False,
            details=f"Exception: {e}",
            duration=time.time() - start,
            category="Data Accuracy",
        ))

    return results


# ---------------------------------------------------------------------------
# Category 3: Hallucination Resistance — does the agent refuse to fabricate?
# ---------------------------------------------------------------------------

def eval_hallucination_resistance(agent) -> list[EvalResult]:
    """Test that the agent doesn't fabricate data for nonexistent entries."""
    results = []

    # Test 1: Nonexistent CVE
    start = time.time()
    try:
        response = agent("What is the CVSS score for CVE-2099-99999?")
        resp_text = str(response).lower()
        hallucinated = any(
            phrase in resp_text
            for phrase in ["cvss score is", "has a cvss of", "scored a"]
            if "not found" not in resp_text and "no data" not in resp_text and "doesn't exist" not in resp_text
        )
        passed = not hallucinated or any(
            phrase in resp_text
            for phrase in [
                "not found", "no data", "doesn't exist", "not in", "no record",
                "no results", "could not find", "don't have", "does not exist",
                "no information", "not present", "no matching", "not available",
            ]
        )
        results.append(EvalResult(
            name="Reject nonexistent CVE (CVE-2099-99999)",
            passed=passed,
            details=f"Response should indicate CVE not found. Got: {resp_text[:100]}",
            duration=time.time() - start,
            category="Hallucination Resistance",
        ))
    except Exception as e:
        results.append(EvalResult(
            name="Reject nonexistent CVE",
            passed=False,
            details=f"Exception: {e}",
            duration=time.time() - start,
            category="Hallucination Resistance",
        ))

    # Test 2: Nonexistent advisory
    start = time.time()
    try:
        response = agent("Tell me about advisory SA-9999")
        resp_text = str(response).lower()
        passed = any(
            phrase in resp_text
            for phrase in [
                "not found", "no data", "doesn't exist", "not in", "no record",
                "no advisory", "no results", "could not find", "don't have",
                "does not exist", "no information", "not present", "no matching",
                "not available",
            ]
        )
        results.append(EvalResult(
            name="Reject nonexistent advisory (SA-9999)",
            passed=passed,
            details=f"Response should indicate advisory not found. Got: {resp_text[:100]}",
            duration=time.time() - start,
            category="Hallucination Resistance",
        ))
    except Exception as e:
        results.append(EvalResult(
            name="Reject nonexistent advisory",
            passed=False,
            details=f"Exception: {e}",
            duration=time.time() - start,
            category="Hallucination Resistance",
        ))

    return results


# ---------------------------------------------------------------------------
# Category 4: Multi-Step Reasoning — can the agent chain tools?
# ---------------------------------------------------------------------------

def eval_multi_step(agent) -> list[EvalResult]:
    """Test that the agent can chain multiple tools for complex queries."""
    results = []

    # Test: Cross-reference patterns with rule coverage
    start = time.time()
    try:
        response = agent(
            "Which of the top 3 recurring CWE patterns have Semgrep rule coverage, "
            "and which ones don't? List them with their counts."
        )
        resp_text = str(response).lower()
        has_cwe_ref = "cwe-" in resp_text
        has_coverage_analysis = any(
            phrase in resp_text
            for phrase in ["coverage", "rule", "semgrep", "covered", "not covered", "no rule", "has rule"]
        )
        passed = has_cwe_ref and has_coverage_analysis
        results.append(EvalResult(
            name="Cross-reference CWE patterns with rule coverage",
            passed=passed,
            details=f"Should reference CWE IDs and coverage status. CWE ref: {has_cwe_ref}, Coverage analysis: {has_coverage_analysis}",
            duration=time.time() - start,
            category="Multi-Step Reasoning",
        ))
    except Exception as e:
        results.append(EvalResult(
            name="Cross-reference CWE patterns with rule coverage",
            passed=False,
            details=f"Exception: {e}",
            duration=time.time() - start,
            category="Multi-Step Reasoning",
        ))

    return results


# ---------------------------------------------------------------------------
# Category 5: Escalation Judgment — does the agent prioritize correctly?
# ---------------------------------------------------------------------------

def eval_escalation_judgment(agent) -> list[EvalResult]:
    """Test that the agent correctly identifies high-priority items."""
    results = []

    start = time.time()
    try:
        response = agent(
            "Which CVEs should be our top priority to address? "
            "Consider CVSS score, EPSS exploit probability, and KEV status."
        )
        resp_text = str(response).lower()
        mentions_kev = "kev" in resp_text or "known exploited" in resp_text
        mentions_cvss = "cvss" in resp_text or "critical" in resp_text or "9." in resp_text
        mentions_epss = "epss" in resp_text or "exploit" in resp_text or "probability" in resp_text
        uses_multiple_signals = sum([mentions_kev, mentions_cvss, mentions_epss]) >= 2

        passed = uses_multiple_signals
        results.append(EvalResult(
            name="Prioritize using multiple risk signals",
            passed=passed,
            details=f"KEV: {mentions_kev}, CVSS: {mentions_cvss}, EPSS: {mentions_epss}. Should use >=2 signals.",
            duration=time.time() - start,
            category="Escalation Judgment",
        ))
    except Exception as e:
        results.append(EvalResult(
            name="Prioritize using multiple risk signals",
            passed=False,
            details=f"Exception: {e}",
            duration=time.time() - start,
            category="Escalation Judgment",
        ))

    return results


# ---------------------------------------------------------------------------
# Category 6: Cross-Project Bridge — advisory patterns vs infrastructure
# ---------------------------------------------------------------------------

def eval_cross_project(agent) -> list[EvalResult]:
    """Test the advisory-intel ↔ ComplianceGuard bridge."""
    results = []

    # Test 1: Infrastructure scan
    start = time.time()
    try:
        response = agent("Scan the live infrastructure for compliance violations.")
        resp_text = str(response).lower()
        has_scan_data = any(
            phrase in resp_text
            for phrase in ["container", "finding", "violation", "compliant", "scanned", "not available", "cannot connect"]
        )
        results.append(EvalResult(
            name="Infrastructure scan returns container data",
            passed=has_scan_data,
            details=f"Should reference containers or findings. Got: {resp_text[:120]}",
            duration=time.time() - start,
            category="Cross-Project Bridge",
        ))
    except Exception as e:
        results.append(EvalResult(
            name="Infrastructure scan returns container data",
            passed=False,
            details=f"Exception: {e}",
            duration=time.time() - start,
            category="Cross-Project Bridge",
        ))

    # Test 2: Cross-reference (the closed loop)
    start = time.time()
    try:
        response = agent(
            "Cross-reference our top CWE patterns with infrastructure compliance. "
            "Which advisory weakness classes overlap with container security gaps?"
        )
        resp_text = str(response).lower()
        has_cwe = "cwe-" in resp_text
        has_infra = any(
            phrase in resp_text
            for phrase in ["container", "privileged", "capabilities", "compliance", "infrastructure", "not available"]
        )
        has_mapping = any(
            phrase in resp_text
            for phrase in ["overlap", "cross-reference", "map", "match", "risk", "gap", "finding", "violation"]
        )
        passed = has_cwe and has_infra and has_mapping
        results.append(EvalResult(
            name="Cross-reference CWE patterns with infrastructure",
            passed=passed,
            details=f"CWE ref: {has_cwe}, Infra ref: {has_infra}, Mapping: {has_mapping}",
            duration=time.time() - start,
            category="Cross-Project Bridge",
        ))
    except Exception as e:
        results.append(EvalResult(
            name="Cross-reference CWE patterns with infrastructure",
            passed=False,
            details=f"Exception: {e}",
            duration=time.time() - start,
            category="Cross-Project Bridge",
        ))

    return results


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all_evals(quick: bool = False):
    """Run the full eval suite."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY required for evals.")
        sys.exit(1)

    init_db()
    suite = EvalSuite()

    # Import here to avoid import errors if strands not installed
    from agent import create_agent

    print("Creating agent for evaluation...")
    agent = create_agent()

    if quick:
        print("Running quick evals (tool selection only)...\n")
        for result in eval_tool_selection(agent):
            suite.add(result)
            icon = "PASS" if result.passed else "FAIL"
            print(f"  [{icon}] {result.name}")
    else:
        print("Running full eval suite...\n")

        print("  [1/6] Tool Selection")
        for result in eval_tool_selection(agent):
            suite.add(result)
            icon = "PASS" if result.passed else "FAIL"
            print(f"    [{icon}] {result.name}")

        print("  [2/6] Data Accuracy")
        for result in eval_data_accuracy(agent):
            suite.add(result)
            icon = "PASS" if result.passed else "FAIL"
            print(f"    [{icon}] {result.name}")

        print("  [3/6] Hallucination Resistance")
        for result in eval_hallucination_resistance(agent):
            suite.add(result)
            icon = "PASS" if result.passed else "FAIL"
            print(f"    [{icon}] {result.name}")

        print("  [4/6] Multi-Step Reasoning")
        for result in eval_multi_step(agent):
            suite.add(result)
            icon = "PASS" if result.passed else "FAIL"
            print(f"    [{icon}] {result.name}")

        print("  [5/6] Escalation Judgment")
        for result in eval_escalation_judgment(agent):
            suite.add(result)
            icon = "PASS" if result.passed else "FAIL"
            print(f"    [{icon}] {result.name}")

        print("  [6/6] Cross-Project Bridge")
        for result in eval_cross_project(agent):
            suite.add(result)
            icon = "PASS" if result.passed else "FAIL"
            print(f"    [{icon}] {result.name}")

    print(suite.summary())

    # Write results to JSON for tracking
    results_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total": len(suite.results),
        "passed": sum(1 for r in suite.results if r.passed),
        "results": [
            {
                "name": r.name,
                "passed": r.passed,
                "details": r.details,
                "duration": round(r.duration, 2),
                "category": r.category,
            }
            for r in suite.results
        ],
    }

    results_path = os.path.join(os.path.dirname(__file__), "..", "data", "eval_results.json")
    os.makedirs(os.path.dirname(results_path), exist_ok=True)
    with open(results_path, "w") as f:
        json.dump(results_data, f, indent=2)
    print(f"Results saved to data/eval_results.json")


if __name__ == "__main__":
    quick = "--quick" in sys.argv
    run_all_evals(quick=quick)
