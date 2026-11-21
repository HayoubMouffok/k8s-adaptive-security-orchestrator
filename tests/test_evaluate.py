import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "attacks"))
from evaluate import evaluate, report

SCEN = [
    {"id": "B1", "label": "benign", "expected": "none", "start": "2026-11-20T10:00:00.000Z", "replay_blocked": None},
    {"id": "M1", "label": "malicious", "expected": "sensitive_file_access",
     "start": "2026-11-20T10:01:00.000Z", "replay_blocked": True},
    {"id": "M2", "label": "malicious", "expected": "network_activity",
     "start": "2026-11-20T10:02:00.000Z", "replay_blocked": False},
]
EVENTS = [
    {"alert_time": "2026-11-20T10:01:01+00:00", "action": "block", "threat_type": "sensitive_file_access",
     "latency_s": 0.4},
    {"alert_time": "2026-11-20T10:05:00+00:00", "action": "ignored", "threat_type": "unknown"},
]


def test_metrics():
    r = evaluate(SCEN, EVENTS)
    assert r["detection_rate"] == 0.5
    assert r["false_positive_rate"] == 0.0
    assert r["block_rate"] == 0.5
    assert r["latency_median_s"] == 0.4
    assert "Taux de détection" in report(r)


def test_alert_belongs_to_latest_scenario_only():
    scen = [
        {"id": "B1", "label": "benign", "expected": "none", "start": "2026-11-20T10:00:00.000Z",
         "replay_blocked": None},
        {"id": "M2", "label": "malicious", "expected": "network_activity",
         "start": "2026-11-20T10:00:08.000Z", "replay_blocked": True},
    ]
    evts = [{"alert_time": "2026-11-20T10:00:10+00:00", "action": "block",
             "threat_type": "network_activity", "latency_s": 0.07}]
    r = evaluate(scen, evts)
    assert r["false_positive_rate"] == 0.0 and r["detection_rate"] == 1.0
