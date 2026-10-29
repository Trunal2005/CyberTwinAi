"""Consistent SQLite online backup before a local schema upgrade; never deletes data."""

import sqlite3
import sys
import os
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from datetime import datetime, timezone
from sqlalchemy.engine import make_url
from backend.db import DATABASE_URL

if __name__ == "__main__":
    url = make_url(DATABASE_URL)
    if url.drivername != "sqlite":
        raise SystemExit(
            "Use your PostgreSQL backup tool before migration; automatic backup is SQLite-only"
        )
    path = Path(url.database or "")
    if path.is_file():
        out = Path(".cache/backups")
        out.mkdir(parents=True, exist_ok=True)
        target = out / (
            "cybertwin-"
            + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
            + ".db"
        )
        with sqlite3.connect(path) as src, sqlite3.connect(target) as dest:
            src.backup(dest)
        model = Path(os.getenv("MODEL_PATH", "data/model.joblib"))
        for source in [model, model.with_suffix(".json")]:
            if source.is_file():
                shutil.copy2(source, out / (target.stem + "-" + source.name))
        print("Consistent SQLite backup saved under ignored .cache/backups/")
    else:
        print("No existing SQLite database; fresh install")
