"""Lab 7.2 - Working Set Analysis (WiredTiger cache)

Dataset: https://github.com/jacobdjwilson/awesome-annual-security-reports (465 real annual reports)

    python labs/lab7_2/lab_02_working_set_analysis.py                    # insert 100k docs + analyse + 60 s reads
    python labs/lab7_2/lab_02_working_set_analysis.py --reads-only       # skip the insert
    python labs/lab7_2/lab_02_working_set_analysis.py --small-cache 128  # also repeat reads with a 128 MB cache

Tip for a *cold* cache (to watch the hit ratio climb from low to ~100 %):
    brew services restart mongodb-community@8.0
    python labs/lab7_2/lab_02_working_set_analysis.py --reads-only
"""
import argparse
import os
import random
import sys
import time
from datetime import datetime, timezone

_LABS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [_LABS, os.path.dirname(_LABS)]          # labs/ (common.py) + project root (backend/)

import bson  # noqa: E402
from pymongo import ASCENDING  # noqa: E402
from rich.progress import Progress  # noqa: E402
from rich.table import Table  # noqa: E402

from backend.app import ingest, labs  # noqa: E402
from common import banner, client, config, connect, console, get_db, get_lab_db, human, save_output  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = 2048          # bytes per document
N_DOCS = 100_000
COLL = "ws_reports"


def load_dataset():
    db = get_db()
    if db.annual_reports.estimated_document_count() == 0:
        console.print("Downloading the annual security reports list from GitHub ...")
        ingest.seed_catalog(db)
        ingest.import_annual_reports(db, log=console.print)
    reports = list(db.annual_reports.find({}, {"first_seen": 0}))
    if not reports:
        console.print("[red]Could not load the dataset (no internet?).[/red]")
        sys.exit(1)
    console.print(f"[green][OK][/green] Dataset: {len(reports)} real reports "
                  f"({min(r['year'] for r in reports)}-{max(r['year'] for r in reports)})")
    return reports


def make_doc(i, src, filler):
    doc = {
        "seq": i,
        "report_id": src["_id"],
        "organization": src["organization"],
        "title": src["title"],
        "year": src["year"],
        "category": src["category"],
        "report_type": src["report_type"],
        "pdf_url": src["pdf_url"],
        "summary": src["summary"],
        "copy_no": i // 1000,
        "ingested_at": datetime.now(timezone.utc),
        "notes": "",
    }
    pad = TARGET - len(bson.encode(doc))
    if pad > 0:
        doc["notes"] = (filler * (pad // len(filler) + 1))[:pad]        # 1 ASCII char = 1 byte
    else:
        doc["summary"] = doc["summary"][:max(0, len(doc["summary"]) + pad)]
    return doc


def insert_docs(reports):
    col = get_lab_db()[COLL]
    col.drop()
    filler = " ".join(r["summary"] for r in reports[:40]).encode("ascii", "ignore").decode() + " "
    t0 = time.perf_counter()
    batch = []
    with Progress(console=console) as prog:
        task = prog.add_task(f"Inserting {N_DOCS:,} documents of ~{TARGET} B", total=N_DOCS)
        for i in range(N_DOCS):
            batch.append(make_doc(i, reports[i % len(reports)], filler))
            if len(batch) == 5000:
                col.insert_many(batch, ordered=False)
                prog.advance(task, len(batch))
                batch = []
        if batch:
            col.insert_many(batch, ordered=False)
            prog.advance(task, len(batch))
    secs = time.perf_counter() - t0
    col.create_index([("seq", ASCENDING)], unique=True)
    console.print(f"[green][OK][/green] Inserted {N_DOCS:,} documents in {secs:.1f} s ({N_DOCS / secs:,.0f} docs/s); "
                  f"index on seq created")
    s = list(col.aggregate([{"$project": {"s": {"$bsonSize": "$$ROOT"}}},
                            {"$group": {"_id": None, "avg": {"$avg": "$s"}, "min": {"$min": "$s"}, "max": {"$max": "$s"}}}]))[0]
    console.print(f"  $bsonSize check: avg {s['avg']:.0f} B, min {s['min']} B, max {s['max']} B")
    return {"seconds": round(secs, 2), "avg_bytes": round(s["avg"], 1), "min": s["min"], "max": s["max"]}


def print_snapshot(snap, title):
    c = snap["counters"]
    t = Table(title=title)
    t.add_column("Metric")
    t.add_column("Value", justify="right")
    t.add_column("Meaning", style="dim")
    t.add_row("Cache size (maximum bytes configured)", human(c["max_bytes"]), "default = 50% of (RAM - 1 GB)")
    t.add_row("Bytes currently in the cache", human(c["used_bytes"]), f"{snap['used_pct']} % of the cache")
    t.add_row("Tracked dirty bytes", human(c["dirty_bytes"]), "changed in memory, not yet on disk")
    t.add_row("Pages requested from the cache", f"{c['pages_requested']:,}", "every page access")
    t.add_row("Pages read into cache", f"{c['pages_read']:,}", "misses: had to come from disk")
    t.add_row("Hit ratio since server start", f"{100 * (snap['hit_ratio_since_start'] or 0):.2f} %",
              "1 - pages read / pages requested")
    cs, ws = snap.get("collection"), snap.get("working_set")
    if cs:
        t.add_row(f"{COLL}: data size / on disk", f"{human(cs['size'])} / {human(cs['storage_size'])}",
                  f"{cs['count']:,} docs, avg {cs['avg_obj']:,} B")
        t.add_row(f"{COLL}: index size", human(cs["index_size"]), "_id + seq")
        t.add_row(f"{COLL}: bytes in cache", human(cs["in_cache"]), f"{ws['collection_in_cache_pct']} % of the data")
        t.add_row("Working set estimate (data + indexes)", human(ws["estimate_bytes"]),
                  f"{100 * ws['ratio_of_cache']:.1f} % of cache -> "
                  + ("[green]fits in RAM[/green]" if ws["fits"] else "[red]does NOT fit - expect disk reads[/red]"))
    console.print(t)


def random_reads(seconds, interval=5.0):
    cl, col = client(), get_lab_db()[COLL]
    n = col.estimated_document_count()
    start = prev = labs.cache_counters(cl.admin.command("serverStatus"))
    t = Table(title=f"Random reads for {seconds} s - hit ratio over time")
    for c in ("Time", "Reads", "Reads/s", "Interval hit ratio", "Cumulative (this test)", "Pages from disk", "Cache used"):
        t.add_column(c, justify="right")
    series, reads, t0 = [], 0, time.perf_counter()
    nxt = t0 + interval
    last_reads = 0
    while time.perf_counter() - t0 < seconds:
        col.find_one({"seq": random.randrange(n)}, {"_id": 0, "seq": 1, "summary": 1})
        reads += 1
        if time.perf_counter() >= nxt:
            cur = labs.cache_counters(cl.admin.command("serverStatus"))
            hr, cum = labs.hit_ratio(prev, cur), labs.hit_ratio(start, cur)
            el = time.perf_counter() - t0
            row = {"t": round(el, 1), "reads": reads, "rps": round((reads - last_reads) / interval),
                   "hit_ratio": hr, "cumulative": cum, "pages_read": cur["pages_read"] - prev["pages_read"],
                   "used_mb": round(cur["used_bytes"] / 1048576, 1)}
            series.append(row)
            colour = "green" if (hr or 0) > 0.95 else "yellow" if (hr or 0) > 0.8 else "red"
            t.add_row(f"{el:5.0f} s", f"{reads:,}", f"{row['rps']:,}", f"[{colour}]{100 * (hr or 0):6.2f} %[/{colour}]",
                      f"{100 * (cum or 0):6.2f} %", f"{row['pages_read']:,}", f"{row['used_mb']:,} MB")
            console.print(f"  t={el:5.0f}s  reads={reads:>8,}  interval hit ratio={100 * (hr or 0):6.2f} %  "
                          f"pages from disk={row['pages_read']:>6,}")
            prev, last_reads, nxt = cur, reads, time.perf_counter() + interval
    console.print(t)
    return series


def set_cache_mb(mb):
    client().admin.command({"setParameter": 1, "wiredTigerEngineRuntimeConfig": f"cache_size={int(mb)}M"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reads-only", action="store_true")
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--small-cache", type=int, default=0, metavar="MB",
                    help="repeat the reads with a temporary smaller cache (e.g. 128) to see the ratio drop")
    args = ap.parse_args()

    banner("Lab 7.2: Working Set Analysis - WiredTiger cache")
    connect()
    out = {"ran_at": datetime.now(timezone.utc)}
    if not args.reads_only:
        banner("Step 1 - Insert 100,000 documents of ~2 KB", "-")
        out["insert"] = insert_docs(load_dataset())
    elif get_lab_db()[COLL].estimated_document_count() == 0:
        console.print("[red]No documents yet - run without --reads-only first.[/red]")
        sys.exit(1)

    banner("Step 2 - db.serverStatus().wiredTiger.cache", "-")
    snap = labs.cache_snapshot(client(), get_lab_db(), COLL)
    print_snapshot(snap, "WiredTiger cache after the insert")
    out["snapshot_before"] = snap

    banner("Step 3 - Random reads: watch the cache hit ratio", "-")
    out["reads"] = random_reads(args.seconds)
    out["snapshot_after"] = labs.cache_snapshot(client(), get_lab_db(), COLL)
    print_snapshot(out["snapshot_after"], "WiredTiger cache after the random reads")

    if args.small_cache:
        orig_mb = snap["counters"]["max_bytes"] // 1048576
        banner(f"Step 4 - Same reads with the cache shrunk to {args.small_cache} MB", "-")
        try:
            set_cache_mb(args.small_cache)
            time.sleep(3)
            out["small_cache"] = {"mb": args.small_cache, "reads": random_reads(max(30, args.seconds // 2))}
            out["small_cache"]["snapshot"] = labs.cache_snapshot(client(), get_lab_db(), COLL)
            print_snapshot(out["small_cache"]["snapshot"], f"Cache limited to {args.small_cache} MB")
        finally:
            set_cache_mb(orig_mb)
            console.print(f"[green]Cache size restored to {orig_mb} MB[/green]")

    r = out["reads"]
    if r:
        console.print(f"\n[bold]Result[/bold]: first interval {100 * (r[0]['hit_ratio'] or 0):.2f} % -> last interval "
                      f"{100 * (r[-1]['hit_ratio'] or 0):.2f} %. The working set "
                      f"({human(snap.get('working_set', {}).get('estimate_bytes', 0))}) "
                      + ("fits in the cache, so after warm-up almost every read is served from RAM."
                         if snap.get("working_set", {}).get("fits") else "is bigger than the cache, so reads keep going to disk."))
    save_output(HERE, "lab_7_2_results.json", out)
    get_db().lab_results.replace_one({"_id": "lab_7_2"}, labs.to_jsonable({"_id": "lab_7_2", **out}), upsert=True)
    banner("Lab 7.2 Complete")


if __name__ == "__main__":
    main()
