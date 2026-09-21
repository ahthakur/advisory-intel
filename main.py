"""Advisory Intel — Arista PSIRT Intelligence Platform.

Usage:
    python main.py scrape      # Scrape Arista security advisories
    python main.py enrich      # Enrich CVEs from NVD, EPSS, CISA KEV
    python main.py classify    # Classify advisories with Claude AI
    python main.py pipeline    # Run full pipeline (scrape + enrich + classify)
    python main.py rules       # Generate Semgrep rules from CWE patterns
    python main.py serve       # Start the dashboard (default: http://localhost:8000)
"""

import asyncio
import sys

from src.db import init_db


def main():
    init_db()

    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1]

    if command == "scrape":
        from src.scraper.arista import scrape_all
        asyncio.run(scrape_all())

    elif command == "enrich":
        from src.enricher.nvd import enrich_all as nvd_enrich
        from src.enricher.epss import enrich_all as epss_enrich
        from src.enricher.kev import enrich_all as kev_enrich
        asyncio.run(nvd_enrich())
        asyncio.run(epss_enrich())
        asyncio.run(kev_enrich())

    elif command == "classify":
        from src.ai.classifier import classify_all
        classify_all()

    elif command == "pipeline":
        from src.scraper.arista import scrape_all
        from src.enricher.nvd import enrich_all as nvd_enrich
        from src.enricher.epss import enrich_all as epss_enrich
        from src.enricher.kev import enrich_all as kev_enrich
        from src.ai.classifier import classify_all
        asyncio.run(scrape_all())
        asyncio.run(nvd_enrich())
        asyncio.run(epss_enrich())
        asyncio.run(kev_enrich())
        classify_all()

    elif command == "rules":
        from src.rules.generator import generate_rules
        generate_rules()

    elif command == "serve":
        import uvicorn
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
        print(f"Starting Advisory Intel dashboard at http://localhost:{port}")
        uvicorn.run("src.api.app:app", host="0.0.0.0", port=port, reload=True)

    else:
        print(f"Unknown command: {command}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
