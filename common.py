"""Shared helpers for the Exercise-7 lab scripts (same style as the course repo's config/connection.py)."""
import json
import os
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bson import json_util  # noqa: E402
from rich.console import Console  # noqa: E402

from backend.app import config  # noqa: E402
from backend.app.db import client, get_db, get_lab_db, ping  # noqa: E402

console = Console()


def connect():
    if not ping():
        console.print(f"[red][X] Cannot reach MongoDB at {config.MONGO_URI}[/red]\n"
                      "    Start it with:  brew services start mongodb-community@8.0")
        sys.exit(1)
    console.print(f"[green][OK][/green] Connected to MongoDB {client().server_info()['version']} at {config.MONGO_URI}")
    return client()


def banner(text, char="="):
    console.print()
    console.print(char * 64, style="bold")
    console.print(f"  {text}", style="bold")
    console.print(char * 64, style="bold")
    console.print()


def human(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:,.1f} TB"


def save_output(folder, name, data):
    out = Path(folder) / "output"
    out.mkdir(exist_ok=True)
    path = out / name
    path.write_text(json.dumps(data, indent=2, default=json_util.default), encoding="utf-8")
    console.print(f"[dim]Saved {path.relative_to(ROOT)}[/dim]")
    return path


__all__ = ["console", "connect", "banner", "human", "save_output", "get_db", "get_lab_db", "client", "config",
           "ROOT", "datetime", "os"]
