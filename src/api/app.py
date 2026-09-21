"""FastAPI application — serves the dashboard and API endpoints."""

import asyncio
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from src.analyzer.patterns import full_analysis, epss_vs_cvss, kev_matches
from src.ai.classifier import generate_insights
from src.rules.generator import generate_rules, get_rules, export_rules_file
from src.db import get_connection, init_db

app = FastAPI(title="Advisory Intel", version="1.0.0")

DASHBOARD_DIR = Path(__file__).parent.parent / "dashboard"
app.mount("/static", StaticFiles(directory=DASHBOARD_DIR / "static"), name="static")
templates = Jinja2Templates(directory=DASHBOARD_DIR / "templates")


@app.on_event("startup")
async def startup():
    init_db()


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/api/summary")
async def api_summary():
    conn = get_connection()
    advisory_count = conn.execute("SELECT COUNT(*) as c FROM advisories").fetchone()["c"]
    cve_count = conn.execute("SELECT COUNT(*) as c FROM cves").fetchone()["c"]
    enriched = conn.execute(
        "SELECT COUNT(*) as c FROM cves WHERE enriched_at IS NOT NULL"
    ).fetchone()["c"]
    classified = conn.execute(
        "SELECT COUNT(*) as c FROM ai_classifications"
    ).fetchone()["c"]
    kev_count = conn.execute(
        "SELECT COUNT(*) as c FROM cves WHERE kev_listed = 1"
    ).fetchone()["c"]
    conn.close()
    return {
        "advisories": advisory_count,
        "cves": cve_count,
        "enriched": enriched,
        "classified": classified,
        "kev_listed": kev_count,
    }


@app.get("/api/analysis")
async def api_analysis():
    return full_analysis()


@app.get("/api/insights")
async def api_insights():
    analysis = full_analysis()
    return {"insights": generate_insights(analysis)}


@app.get("/api/advisories")
async def api_advisories(limit: int = 500, offset: int = 0):
    conn = get_connection()
    rows = conn.execute(
        """SELECT a.id, a.title, a.url, a.published_date, a.scraped_at,
                  COUNT(c.cve_id) as cve_count,
                  MAX(c.cvss_score) as max_cvss,
                  MAX(c.epss_score) as max_epss
           FROM advisories a
           LEFT JOIN cves c ON a.id = c.advisory_id
           GROUP BY a.id
           ORDER BY a.scraped_at DESC
           LIMIT ? OFFSET ?""",
        (limit, offset),
    ).fetchall()
    conn.close()
    return {"advisories": [dict(r) for r in rows]}


@app.get("/api/advisories/{advisory_id}")
async def api_advisory_detail(advisory_id: str):
    conn = get_connection()
    adv = conn.execute(
        "SELECT * FROM advisories WHERE id = ?", (advisory_id,)
    ).fetchone()
    cves = conn.execute(
        "SELECT * FROM cves WHERE advisory_id = ?", (advisory_id,)
    ).fetchall()
    classifications = conn.execute(
        "SELECT * FROM ai_classifications WHERE advisory_id = ?", (advisory_id,)
    ).fetchall()
    conn.close()
    if not adv:
        return {"error": "Not found"}
    return {
        "advisory": dict(adv),
        "cves": [dict(r) for r in cves],
        "classifications": [dict(r) for r in classifications],
    }


@app.get("/api/rules")
async def api_rules():
    rules = get_rules()
    return {"rules": rules, "count": len(rules)}


@app.post("/api/rules/generate")
async def api_generate_rules():
    rules = generate_rules()
    return {"rules": rules, "count": len(rules)}


@app.get("/api/rules/export")
async def api_export_rules():
    from fastapi.responses import PlainTextResponse
    content = export_rules_file()
    return PlainTextResponse(content, media_type="text/yaml",
                             headers={"Content-Disposition": "attachment; filename=arista-advisory-rules.yml"})


@app.post("/api/pipeline/scrape")
async def run_scrape():
    from src.scraper.arista import scrape_all
    await scrape_all()
    return {"status": "complete"}


@app.post("/api/pipeline/enrich")
async def run_enrich():
    from src.enricher.nvd import enrich_all as nvd_enrich
    from src.enricher.epss import enrich_all as epss_enrich
    from src.enricher.kev import enrich_all as kev_enrich
    await nvd_enrich()
    await epss_enrich()
    await kev_enrich()
    return {"status": "complete"}


@app.post("/api/pipeline/classify")
async def run_classify():
    from src.ai.classifier import classify_all
    classify_all()
    return {"status": "complete"}


@app.post("/api/pipeline/full")
async def run_full_pipeline():
    from src.scraper.arista import scrape_all
    from src.enricher.nvd import enrich_all as nvd_enrich
    from src.enricher.epss import enrich_all as epss_enrich
    from src.enricher.kev import enrich_all as kev_enrich
    from src.ai.classifier import classify_all

    await scrape_all()
    await nvd_enrich()
    await epss_enrich()
    await kev_enrich()
    classify_all()
    return {"status": "complete"}
