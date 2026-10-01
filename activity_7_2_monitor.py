"""Activity 7.2 - Cache monitoring script.

Every 10 seconds it reads db.serverStatus().wiredTiger.cache and reports the cache hit ratio.
In the background it browses for NEWER threat reports (security news feeds + the annual-reports
list on GitHub) and inserts only the ones not already in the database.

    python labs/lab7_2/activity_7_2_monitor.py                     # run until Ctrl+C
    python labs/lab7_2/activity_7_2_monitor.py --workload          # also generate random reads on ws_reports
    python labs/lab7_2/activity_7_2_monitor.py --duration 300 --browse-every 120

Output: console table + labs/lab7_2/output/cache_monitor.csv + capped collection cti_platform.cache_metrics
(the website's Cache lab page draws its live chart from that collection).
"""
import argparse
import asyncio
import csv
import os
import random
import sys
import threading
import time
from datetime import datetime, timezone

_LABS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [_LABS, os.path.dirname(_LABS)]          # labs/ (common.py) + project root (backend/)

from backend.app import ingest, labs  # noqa: E402
from common import banner, client, connect, console, get_db, get_lab_db  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = {"new_reports": 0, "last_titles": [], "browsing": False, "last_browse": None, "errors": 0}


def browse_once():
    """Look for newer reports and insert only the ones the database does not have yet."""
    db = get_db()
    STATE["browsing"] = True
    try:
        before = db.reports.estimated_document_count()
        res = asyncio.run(ingest.ingest_news(db, log=lambda *_: None))
        ann = ingest.import_annual_reports(db, log=lambda *_: None)
        new_titles = [r["title"] for r in db.reports.find({}, {"title": 1}).sort("fetched_at", -1)
                      .limit(res["new_reports"])] if res["new_reports"] else []
        new_titles += [f"[annual] {a['organization']} - {a['title']} ({a['year']})" for a in ann.get("new", [])]
        n = res["new_reports"] + len(ann.get("new", []))
        STATE["new_reports"] += n
        STATE["last_titles"] = new_titles[:3]
        STATE["last_browse"] = datetime.now(timezone.utc)
        STATE["errors"] = sum(1 for r in res["results"] if r["status"] != "ok")
        return n, before
    finally:
        STATE["browsing"] = False


def browser_loop(every, stop):
    while not stop.is_set():
        try:
            n, _ = browse_once()
            if n:
                console.print(f"  [cyan]+{n} new threat report(s) stored[/cyan]: " + " | ".join(t[:70] for t in STATE["last_titles"]))
        except Exception as exc:
            console.print(f"  [yellow]browse failed: {exc}[/yellow]")
        stop.wait(every)


def workload_loop(stop):
    col = get_lab_db()["ws_reports"]
    n = col.estimated_document_count()
    if not n:
        console.print("[yellow]--workload needs Lab 7.2 data (run lab_02_working_set_analysis.py first)[/yellow]")
        return
    while not stop.is_set():
        col.find_one({"seq": random.randrange(n)}, {"_id": 0, "seq": 1})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=10.0, help="seconds between samples (default 10)")
    ap.add_argument("--browse-every", type=float, default=60.0, help="seconds between report checks (default 60)")
    ap.add_argument("--duration", type=float, default=0, help="stop after N seconds (default: until Ctrl+C)")
    ap.add_argument("--workload", action="store_true", help="generate random reads so the ratio moves")
    args = ap.parse_args()

    banner("Activity 7.2: WiredTiger cache monitor")
    connect()
    db, cl = get_db(), client()
    stop = threading.Event()
    threading.Thread(target=browser_loop, args=(args.browse_every, stop), daemon=True).start()
    if args.workload:
        threading.Thread(target=workload_loop, args=(stop,), daemon=True).start()

    out_dir = os.path.join(HERE, "output")
    os.makedirs(out_dir, exist_ok=True)
    csv_path = os.path.join(out_dir, "cache_monitor.csv")
    fresh = not os.path.exists(csv_path)
    f = open(csv_path, "a", newline="")
    w = csv.writer(f)
    if fresh:
        w.writerow(["time_utc", "interval_hit_ratio", "cumulative_hit_ratio", "cache_used_mb", "cache_used_pct",
                    "dirty_pct", "pages_requested", "pages_read", "evicted", "app_evictions", "new_reports_total"])

    console.print(f"Sampling every {args.interval:.0f} s, browsing for new reports every {args.browse_every:.0f} s. "
                  "Press Ctrl+C to stop.\n")
    console.print(f"{'time':>8}  {'hit ratio':>10}  {'since start':>11}  {'cache used':>12}  {'dirty':>7}  "
                  f"{'from disk':>9}  {'evicted':>8}  {'new rpts':>8}")
    start = prev = labs.cache_counters(cl.admin.command("serverStatus"))
    t0 = time.time()
    try:
        while not args.duration or time.time() - t0 < args.duration:
            time.sleep(args.interval)
            st = cl.admin.command("serverStatus")
            cur = labs.cache_counters(st)
            hr, cum = labs.hit_ratio(prev, cur), labs.hit_ratio(start, cur)
            evicted = (cur["evicted_unmodified"] + cur["evicted_modified"]) - (prev["evicted_unmodified"] + prev["evicted_modified"])
            app_ev = cur["evicted_by_app"] - prev["evicted_by_app"]
            used_pct = 100 * cur["used_bytes"] / cur["max_bytes"] if cur["max_bytes"] else 0
            dirty_pct = 100 * cur["dirty_bytes"] / cur["max_bytes"] if cur["max_bytes"] else 0
            now = datetime.now(timezone.utc)
            hr_txt = "   idle" if hr is None else f"{100 * hr:6.2f} %"
            colour = "white" if hr is None else "green" if hr > 0.95 else "yellow" if hr > 0.8 else "red"
            console.print(f"{now:%H:%M:%S}  [{colour}]{hr_txt:>10}[/{colour}]  {100 * (cum or 0):10.2f}%  "
                          f"{cur['used_bytes'] / 1048576:9.1f} MB  {dirty_pct:6.2f}%  "
                          f"{cur['pages_read'] - prev['pages_read']:>9,}  {evicted:>8,}  {STATE['new_reports']:>8}"
                          + ("  [dim](browsing...)[/dim]" if STATE["browsing"] else ""))
            if app_ev > 0:
                console.print(f"          [red]! {app_ev} pages evicted by application threads - cache under pressure[/red]")
            sample = {"at": now, "hit_ratio": hr, "cumulative": cum, "used_bytes": cur["used_bytes"],
                      "max_bytes": cur["max_bytes"], "used_pct": round(used_pct, 2), "dirty_pct": round(dirty_pct, 3),
                      "pages_requested": cur["pages_requested"] - prev["pages_requested"],
                      "pages_read": cur["pages_read"] - prev["pages_read"], "evicted": evicted,
                      "app_evictions": app_ev, "new_reports": STATE["new_reports"]}
            db.cache_metrics.insert_one(sample)
            w.writerow([now.isoformat(), hr, cum, round(cur["used_bytes"] / 1048576, 1), round(used_pct, 2),
                        round(dirty_pct, 3), sample["pages_requested"], sample["pages_read"], evicted, app_ev,
                        STATE["new_reports"]])
            f.flush()
            prev = cur
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        f.close()
        console.print(f"\n[green]Stopped.[/green] {STATE['new_reports']} new report(s) stored. CSV log: {csv_path}")
    banner("Activity 7.2 Complete")


if __name__ == "__main__":
    main()
