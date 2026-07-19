from domainrecon.compare import compare_results


def test_compare_reports_new_removed_and_changed_assets():
    baseline = {
        "scan_id": "old",
        "assets": [
            {"kind": "domain", "value": "old.example.com", "attributes": {}},
            {"kind": "ip", "value": "203.0.113.1", "attributes": {"status": "old"}},
        ],
    }
    current = {
        "assets": [
            {"kind": "domain", "value": "new.example.com", "attributes": {}},
            {"kind": "ip", "value": "203.0.113.1", "attributes": {"status": "new"}},
        ]
    }
    comparison = compare_results(current, baseline)
    assert comparison["baseline_scan_id"] == "old"
    assert comparison["new_assets"][0]["value"] == "new.example.com"
    assert comparison["removed_assets"][0]["value"] == "old.example.com"
    assert comparison["changed_assets"][0]["key"] == "ip:203.0.113.1"
