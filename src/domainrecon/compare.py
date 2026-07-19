from __future__ import annotations

from typing import Any


def compare_results(current: dict[str, Any], baseline: dict[str, Any] | None) -> dict[str, Any]:
    if not baseline:
        return {
            "baseline_scan_id": None,
            "new_assets": [],
            "removed_assets": [],
            "changed_assets": [],
        }
    old = {_key(asset): asset for asset in baseline.get("assets", [])}
    new = {_key(asset): asset for asset in current.get("assets", [])}
    changed = [
        {
            "key": key,
            "before": old[key].get("attributes", {}),
            "after": new[key].get("attributes", {}),
        }
        for key in old.keys() & new.keys()
        if old[key].get("attributes", {}) != new[key].get("attributes", {})
    ]
    return {
        "baseline_scan_id": baseline.get("scan_id"),
        "new_assets": [new[key] for key in sorted(new.keys() - old.keys())],
        "removed_assets": [old[key] for key in sorted(old.keys() - new.keys())],
        "changed_assets": changed,
    }


def _key(asset: dict[str, Any]) -> str:
    return f"{asset.get('kind', '')}:{str(asset.get('value', '')).lower()}"
