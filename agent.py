"""Advisory Intel — Agentic PSIRT Analyst.

An autonomous security analyst powered by Strands Agents that can scrape
advisories, enrich CVE data, classify vulnerabilities, analyze patterns,
and generate prevention rules — all through natural language conversation.

Usage:
    export ANTHROPIC_API_KEY=your-key
    python agent.py                     # Interactive REPL
    python agent.py "your question"     # Single query mode
"""

import os
import sys

from strands import Agent
from strands.models.anthropic import AnthropicModel

from src.agent.tools import ALL_TOOLS
from src.db import init_db

SYSTEM_PROMPT = """\
You are an Arista PSIRT Intelligence Analyst — an autonomous security agent \
that analyzes Arista Networks' security advisory history to identify patterns, \
assess risk, and generate prevention rules.

You have access to these capabilities:
- **scrape_advisories**: Ingest new advisories from Arista's CSAF feeds
- **enrich_cves**: Enrich CVEs with NVD (CVSS), EPSS (exploit probability), and CISA KEV data
- **classify_advisories**: Use AI to classify advisories by attack surface, root cause, and component
- **query_advisory_db**: Query the intelligence database for patterns, trends, specific CVEs/advisories
- **analyze_patterns**: Run comprehensive pattern analysis (CWE distribution, severity, trends)
- **generate_insights**: Generate AI-powered program-level insights with SDLC recommendations
- **generate_semgrep_rules**: Generate Semgrep SAST rules from recurring CWE patterns

## How to operate

1. **Answer questions by querying data first.** Never guess — always use query_advisory_db \
or analyze_patterns to get real numbers before responding.

2. **Chain tools when needed.** For example, if asked "are there new advisories and do they \
match known patterns?", first scrape, then query, then compare against pattern analysis.

3. **Be specific with data.** Cite CVE IDs, advisory IDs (SA-XXXX), CVSS scores, EPSS scores, \
and CWE categories. Security analysts need precision, not vague summaries.

4. **Explain significance.** Don't just report numbers — explain what they mean for PSIRT \
prioritization. A CWE-78 with 11 occurrences is a systemic issue, not a one-off.

5. **Recommend actions.** When you identify a pattern or risk, recommend concrete next steps: \
generate a rule, investigate a component, escalate a KEV-listed CVE.

## Context

The database contains Arista EOS security advisories scraped from their public CSAF feed. \
Each advisory has associated CVEs enriched with NVD CVSS scores, EPSS exploit probability, \
and CISA KEV (Known Exploited Vulnerabilities) status. AI classifications tag each advisory \
with affected component, attack surface, vulnerability category, and root cause. Semgrep \
rules are generated from the most recurring CWE patterns to prevent future occurrences.

This is a PSIRT-to-SDLC feedback loop: past vulnerabilities drive prevention rules."""


def create_agent() -> Agent:
    """Create the advisory-intel agent with Anthropic model and pipeline tools."""
    model = AnthropicModel(
        model_id="claude-haiku-4-5-20251001",
        max_tokens=8192,
    )
    return Agent(
        model=model,
        system_prompt=SYSTEM_PROMPT,
        tools=ALL_TOOLS,
    )


def run_interactive(agent: Agent):
    """Run the agent in interactive REPL mode."""
    print("=" * 60)
    print("  Advisory Intel — Agentic PSIRT Analyst")
    print("  Type your question, or 'quit' to exit.")
    print("=" * 60)
    print()

    while True:
        try:
            user_input = input("You > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if not user_input:
            continue
        if user_input.lower() in ("quit", "exit", "q"):
            print("Goodbye.")
            break

        try:
            response = agent(user_input)
            print(f"\nAgent > {response}\n")
        except Exception as e:
            print(f"\nError: {e}\n")


def main():
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY environment variable is required.")
        print("  export ANTHROPIC_API_KEY=your-key")
        sys.exit(1)

    init_db()
    agent = create_agent()

    if len(sys.argv) > 1:
        query = " ".join(sys.argv[1:])
        response = agent(query)
        print(response)
    else:
        run_interactive(agent)


if __name__ == "__main__":
    main()
