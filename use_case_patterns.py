"""MongoDB use cases (classroom update) - run all six "where MongoDB fits" patterns on the CTI platform.

    python labs/use_cases/use_case_patterns.py                   # all six (about 10-30 s)
    python labs/use_cases/use_case_patterns.py --only timeseries --events 100000
    python labs/use_cases/use_case_patterns.py --only content catalog

Use case -> pattern -> collection
  1 Content management   embedded content blocks              briefings.blocks[]
  2 Product catalog      schema validation, flexible fields    $jsonSchema on indicators
  3 User profiles        embed preferences, reference history analysts + lookup_history.analyst_id
  4 IoT data ingestion   time-series collection (5.0+)         feed_telemetry (+ write benchmark)
  5 Real-time analytics  pre-aggregated buckets + raw data     report_stats_daily vs reports
  6 Mobile apps          change streams + local data           ReportSync / /api/stream (resume token)

Results: console + labs/use_cases/output/use_cases.json + cti_platform.lab_results {_id: "use_cases"}
(the website's "Use cases" page shows the same results).
"""
import argparse
import os
import sys

_LABS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [_LABS, os.path.dirname(_LABS)]          # labs/ (common.py) + project root (backend/)

from rich.table import Table  # noqa: E402

from backend.app import usecases  # noqa: E402
from common import banner, client, connect, console, get_db, human, save_output  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def show(uc, r):
    console.rule(f"[bold]{uc['n']}. {uc['use_case']}[/bold]  -  {uc['pattern']}")
    console.print(f"[dim]Why MongoDB fits: {uc['why']}.  Here: {uc['where']}[/dim]")
    if not r.get("ok"):
        console.print(f"[red]Failed:[/red] {r.get('error')}")
        return
    k = uc["key"]
    if k == "content":
        console.print(f"Briefing [cyan]{r['briefing_id']}[/cyan] v{r['version']}: {r['blocks']} blocks "
                      f"({', '.join(r['block_types'])}), {r['bson_bytes']:,} bytes, read in {r['read_ms']} ms")
        console.print(f"Query into nested blocks {r['query']} -> {r['briefings_with_kev_cve_table']} briefing(s)")
    elif k == "catalog":
        t = Table(title=f"Indicator 'catalog' - fields per type (validator on: {r['validator_enabled']})")
        t.add_column("type", style="cyan")
        t.add_column("sampled", justify="right")
        t.add_column("fields")
        for s in r["shapes"]:
            t.add_row(str(s["type"]), f"{s['sampled']:,}", ", ".join(f for f in s["fields"] if f != "_id"))
        console.print(t)
        t = Table(title="Validator test inserts")
        for c in ("case", "result", "detail"):
            t.add_column(c)
        for x in r["tests"]:
            t.add_row(x["case"], "[green]accepted[/green]" if x["accepted"] else "[red]rejected[/red]", x["detail"])
        console.print(t)
    elif k == "profiles":
        console.print(f"Profile (embedded preferences): {r['profile_bytes']} bytes, {r['profile_read_ms']} ms per read")
        console.print(f"Activity (referenced): {r['activity_total']:,} lookups, newest 20 in {r['activity_page_ms']} ms "
                      f"using {r['activity_plan']}")
    elif k == "timeseries":
        t = Table(title=f"{r['events']:,} observation events written in batches of {r['batch']:,}")
        for c in ("collection", "writes/s", "storage", "indexes", "buckets", "2-day hourly rollup"):
            t.add_column(c, justify="right" if c != "collection" else "left")
        for name, label in (("ts_bench_events", "time-series"), ("ts_bench_plain", "regular")):
            x = r[name]
            t.add_row(label, f"{x['writes_per_sec']:,}", human(x["storage"]), human(x["index"]),
                      str(x["buckets"] or "-"), f"{x['rollup_ms']} ms")
        console.print(t)
        console.print(f"Time-series uses [bold]{r['storage_saving_pct']}%[/bold] less disk + index space. "
                      f"feed_telemetry currently holds {r['feed_telemetry_points']:,} real feed measurements.")
    elif k == "analytics":
        console.print(f"Last {r['days']} days: raw aggregation over {r['raw_reports_scanned']:,} reports = "
                      f"{r['raw_ms']} ms;  {r['bucket_docs_read']} daily buckets = {r['bucket_ms']} ms "
                      f"([bold]{r['speedup']}x[/bold] faster). Totals match: {r['totals_match']}")
    elif k == "sync":
        console.print(f"Replica set: {r['replica_set']}  ->  mode: [bold]{r['mode']}[/bold]")
        if r["replica_set"]:
            console.print(f"First event after {r['first_event_latency_ms']} ms. Resumed after 'offline': "
                          f"{r['resumed_events']} (ok = {r['resume_ok']})")
        else:
            console.print("Enable change streams (single-node replica set):")
            for line in r["how_to_enable"]:
                console.print(f"   {line}")
    console.print(f"[green]{r.get('takeaway', '')}[/green]  [dim]({r['seconds']} s)[/dim]\n")


def main():
    ap = argparse.ArgumentParser(description="Run the six MongoDB use-case patterns")
    ap.add_argument("--only", nargs="*", choices=[u["key"] for u in usecases.USE_CASES],
                    help="run only these use cases")
    ap.add_argument("--events", type=int, default=20000, help="events for the time-series benchmark")
    args = ap.parse_args()

    banner("MongoDB use cases - design patterns on the CTI platform")
    connect()
    db = get_db()
    if db.reports.estimated_document_count() == 0:
        console.print("[yellow]The database is empty - run python backend/scripts/setup_database.py first "
                      "(--offline works without internet).[/yellow]")
        sys.exit(1)
    res = usecases.run_all(db, client(), events=args.events, only=args.only, log=show)
    save_output(HERE, "use_cases.json", res)
    keys = args.only or [u["key"] for u in usecases.USE_CASES]
    ok = sum(1 for k in keys if (res.get(k) or {}).get("ok"))
    console.print(f"[bold]{ok}/{len(keys)} use cases ran successfully.[/bold] See them on http://127.0.0.1:8000/#/usecases")


if __name__ == "__main__":
    main()
