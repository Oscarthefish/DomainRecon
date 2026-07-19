from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import ScanResult


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  scan_id TEXT PRIMARY KEY, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  targets_json TEXT NOT NULL, result_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS scans_created_at ON scans(created_at);
"""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)

    def save(self, result: ScanResult) -> None:
        data = json.dumps(result.to_dict(), sort_keys=True)
        self.db.execute(
            "INSERT OR REPLACE INTO scans(scan_id, targets_json, result_json) VALUES (?, ?, ?)",
            (result.scan_id, json.dumps(result.targets), data),
        )
        self.db.commit()

    def latest(self) -> dict | None:
        row = self.db.execute(
            "SELECT result_json FROM scans ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        return json.loads(row[0]) if row else None

    def history(self, limit: int = 50) -> list[dict]:
        rows = self.db.execute(
            "SELECT scan_id, created_at, targets_json, result_json FROM scans ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                "scan_id": row[0],
                "created_at": row[1],
                "targets": json.loads(row[2]),
                "summary": self._summary(json.loads(row[3])),
            }
            for row in rows
        ]

    def previous_for_targets(self, targets: list[str]) -> dict | None:
        wanted = sorted(targets)
        rows = self.db.execute(
            "SELECT targets_json, result_json FROM scans ORDER BY created_at DESC"
        ).fetchall()
        for targets_json, result_json in rows:
            if sorted(json.loads(targets_json)) == wanted:
                return json.loads(result_json)
        return None

    @staticmethod
    def _summary(result: dict) -> dict[str, int]:
        return {
            "assets": len(result.get("assets", [])),
            "relationships": len(result.get("edges", [])),
            "findings": len(result.get("findings", [])),
            "errors": len(result.get("errors", [])),
        }

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
