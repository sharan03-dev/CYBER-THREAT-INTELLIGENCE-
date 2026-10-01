"""Use case 6 (mobile apps / offline sync) - watch new threat reports live, like a phone app would.

    python labs/use_cases/watch_reports.py            # prints each new report; Ctrl+C to stop
    python labs/use_cases/watch_reports.py --demo     # also inserts 3 demo reports (deleted on exit)

On a replica set it uses a change stream and saves the resume token to labs/use_cases/output/resume_token.txt.
Stop it, let new reports arrive (e.g. click "Update now" on the Sources page), start it again: it resumes from
the token and prints exactly the reports it missed while "offline". On a standalone server it falls back to polling.
"""
import argparse
import os
import sys
import threading
import time
from pathlib import Path

_LABS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [_LABS, os.path.dirname(_LABS)]          # labs/ (common.py) + project root (backend/)

from backend.app import usecases  # noqa: E402
from common import banner, connect, console, get_db  # noqa: E402

TOKEN_FILE = Path(__file__).resolve().parent / "output" / "resume_token.txt"
DEMO_URL = "urn:kavach:sync-demo:"


def demo_inserts(db):
    time.sleep(2)
    for i in range(1, 4):
        db.reports.insert_one({
            "source_id": "sample-data", "url": f"{DEMO_URL}{time.time_ns()}", "published_at": usecases.now(),
            "title": f"[demo] Change-stream sync test report {i}", "summary": "Inserted by watch_reports.py --demo",
            "tags": ["demo"], "cve_ids": [], "actor_ids": [], "indicator_ids": [],
            "classification": {"category": "General security", "severity": "Low", "verdict": "Informational"}})
        time.sleep(1.5)


def main():
    ap = argparse.ArgumentParser(description="Watch new reports (change stream or polling)")
    ap.add_argument("--demo", action="store_true", help="insert 3 demo reports while watching")
    ap.add_argument("--fresh", action="store_true", help="ignore the saved resume token")
    args = ap.parse_args()
    banner("Use case 6 - live sync of new threat reports")
    connect()
    db = get_db()
    token = "" if args.fresh or not TOKEN_FILE.exists() else TOKEN_FILE.read_text().strip()
    sync = usecases.ReportSync(db, token)
    TOKEN_FILE.parent.mkdir(exist_ok=True)
    console.print(f"Mode: [bold]{sync.mode}[/bold]" + ("  (resuming from saved token)" if token else ""))
    if sync.resync:
        console.print("[yellow]Saved token is too old for the oplog - starting fresh.[/yellow]")
    if sync.mode == "polling":
        console.print("[dim]Change streams need a replica set. See labs/use_cases/USE_CASES.md section 6.[/dim]")
    if args.demo:
        threading.Thread(target=demo_inserts, args=(db,), daemon=True).start()
    seen = 0
    try:
        while True:
            for tok, card in sync.next_batch(2.0):
                seen += 1
                TOKEN_FILE.write_text(tok)
                when = card["published_at"].strftime("%d %b %H:%M") if card.get("published_at") else ""
                console.print(f"[cyan]{when}[/cyan] [{card.get('severity') or '-'}] {card.get('verdict') or ''}: "
                              f"{card.get('title')}  [dim]({card.get('source_id')})[/dim]")
            if sync.token():
                TOKEN_FILE.write_text(sync.token())
    except KeyboardInterrupt:
        pass
    finally:
        sync.close()
        if args.demo:
            n = db.reports.delete_many({"url": {"$regex": f"^{DEMO_URL}"}}).deleted_count
            console.print(f"[dim]Removed {n} demo reports.[/dim]")
        console.print(f"\n{seen} new report(s) received. Resume token saved to {TOKEN_FILE.name}.")


if __name__ == "__main__":
    main()
