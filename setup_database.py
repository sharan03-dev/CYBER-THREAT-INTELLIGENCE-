"""Build the whole CTI database in one command.

    python backend/scripts/setup_database.py            # everything (about 1-3 minutes)
    python backend/scripts/setup_database.py --reset    # drop cti_platform first, then rebuild
    python backend/scripts/setup_database.py --offline  # no internet: load the built-in sample data only
    python backend/scripts/setup_database.py --news     # only refresh the news reports

Order matters: sources/actors -> CISA KEV -> IOC feeds -> news reports -> ctidigest.com -> annual reports
-> use-case collections (daily buckets, briefing, analyst profile).
"""
import argparse
import asyncio
import os
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from rich.console import Console  # noqa: E402
from rich.table import Table  # noqa: E402

from backend.app import config, ingest, usecases  # noqa: E402
from backend.app.db import client, ensure_indexes, get_db, ping  # noqa: E402

console = Console()


def main():
    ap = argparse.ArgumentParser(description="Build the CTI platform database")
    ap.add_argument("--reset", action="store_true", help="drop the cti_platform database first")
    ap.add_argument("--offline", action="store_true", help="load built-in sample data only")
    ap.add_argument("--news", action="store_true", help="only refresh news reports")
    args = ap.parse_args()

    console.rule("[bold]CTI Platform - database setup")
    if not ping():
        console.print(f"[red]Cannot reach MongoDB at {config.MONGO_URI}[/red]\n"
                      "Start it:  [bold]brew services start mongodb-community@8.0[/bold]")
        sys.exit(1)
    console.print(f"[green]Connected[/green] to MongoDB {client().server_info()['version']} - database "
                  f"[bold]{config.DB_NAME}[/bold]")
    db = get_db()
    if args.reset:
        client().drop_database(config.DB_NAME)
        console.print("[yellow]Dropped existing database[/yellow]")

    t0 = time.perf_counter()
    started = datetime.now(timezone.utc)
    ensure_indexes(db)
    ingest.seed_catalog(db)
    console.print("\n[bold]1. Sources and threat actors[/bold] seeded")

    if args.offline:
        console.print("\n[bold]Offline mode[/bold]")
        ingest.load_sample_data(db, log=console.print)
    else:
        if not args.news:
            console.print("\n[bold]2. CISA Known Exploited Vulnerabilities[/bold]")
            ingest.import_kev(db, log=console.print)
            console.print("\n[bold]3. IP / URL threat feeds[/bold] (this is the biggest step)")
            ingest.import_ioc_feeds(db, log=console.print)
        console.print("\n[bold]4. Threat reports from security news feeds[/bold]")
        news = asyncio.run(ingest.ingest_news(db, log=console.print))
        ingest.log_run(db, "news", started, news)
        if not args.news:
            console.print("\n[bold]5. ctidigest.com (reference platform)[/bold]")
            found = asyncio.run(ingest.discover_ctidigest(db, log=console.print))
            if found.get("feeds_added"):
                console.print(f"  ctidigest listed {found['feeds_added']} extra feeds - fetching them")
                extra = [s["_id"] for s in db.sources.find({"discovered_from": "ctidigest"}, {"_id": 1})]
                asyncio.run(ingest.ingest_news(db, only=extra, log=console.print))
            console.print("\n[bold]6. Annual security reports (Lab 7.2 dataset)[/bold]")
            ingest.import_annual_reports(db, log=console.print)
        if db.reports.estimated_document_count() == 0:
            console.print("\n[yellow]No news could be downloaded - loading offline sample data instead[/yellow]")
            ingest.load_sample_data(db, log=console.print)

    console.print("\n[bold]7. MongoDB use-case patterns[/bold] (buckets, briefing, profile)")
    b = usecases.rebuild_buckets(db)
    console.print(f"  [ok]   report_stats_daily                         {b['buckets']:>7,} daily buckets")
    br = usecases.build_briefing(db)
    console.print(f"  [ok]   briefings                                  {len(br['blocks']):>7} content blocks")
    usecases.ensure_analyst(db)

    tbl = Table(title="cti_platform collections", show_lines=False)
    tbl.add_column("Collection", style="cyan")
    tbl.add_column("Documents", justify="right")
    for c in ["sources", "reports", "indicators", "sightings", "vulnerabilities", "threat_actors", "annual_reports",
              "briefings", "analysts", "report_stats_daily"]:
        tbl.add_row(c, f"{db[c].estimated_document_count():,}")
    console.print()
    console.print(tbl)
    console.print(f"\n[green]Done in {time.perf_counter() - t0:.0f} s.[/green] Start the website with:\n"
                  "  [bold]python -m uvicorn backend.app.main:app --port 8000[/bold]  then open http://127.0.0.1:8000")


if __name__ == "__main__":
    main()
