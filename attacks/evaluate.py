"""Calcule les indicateurs de l'expérience à partir des scénarios joués et des événements de l'orchestrateur.

Usage : python3 evaluate.py results/scenarios.jsonl results/events.json
"""
from __future__ import annotations

import json
import statistics
import sys
from datetime import datetime, timedelta

WINDOW = timedelta(seconds=15)  # une alerte au-delà de ce délai n'est rattachée à aucun scénario


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def evaluate(scenarios: list[dict], events: list[dict]) -> dict:
    acted = [e for e in events if e.get("action") in ("block", "audit")]
    starts = sorted(ts(s["start"]) for s in scenarios)

    def owner(alert_time: datetime) -> datetime | None:
        """Chaque alerte est rattachée au DERNIER scénario lancé avant elle (et non à tous ceux
        de la fenêtre), sinon l'alerte d'une attaque est aussi comptée sur l'action légitime
        qui la précède."""
        before = [st for st in starts if st <= alert_time <= st + WINDOW]
        return before[-1] if before else None

    rows, latencies = [], []
    tp = fn = fp = tn = 0
    for s in scenarios:
        start = ts(s["start"])
        hits = [e for e in acted if owner(ts(e["alert_time"])) == start]
        if s["label"] == "malicious":
            match = [e for e in hits if e["threat_type"] == s["expected"]]
            if match:
                tp += 1
                latencies.append(match[0]["latency_s"])
            else:
                fn += 1
            detected = bool(match)
        else:
            if hits:
                fp += 1
            else:
                tn += 1
            detected = bool(hits)
        rows.append({**s, "detected": detected, "alerts": len(hits)})

    malicious = [r for r in rows if r["label"] == "malicious"]
    blocked = [r for r in malicious if r["replay_blocked"] is True]
    benign_checked = [r for r in rows if r["label"] == "benign" and r["replay_blocked"] is not None]
    preserved = [r for r in benign_checked if r["replay_blocked"] is False]
    return {
        "legit_preserved_rate": len(preserved) / len(benign_checked) if benign_checked else None,
        "rows": rows,
        "detection_rate": tp / (tp + fn) if tp + fn else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "block_rate": len(blocked) / len(malicious) if malicious else 0.0,
        "latency_median_s": statistics.median(latencies) if latencies else None,
        "latency_max_s": max(latencies) if latencies else None,
    }


def report(r: dict) -> str:
    lines = ["# Résultats de l'évaluation", "",
             "| Scénario | Nature | Type attendu | Détecté | 2e essai bloqué |",
             "|---|---|---|---|---|"]
    for x in r["rows"]:
        rb = {True: "oui", False: "non", None: "-"}[x["replay_blocked"]]
        lines.append(f"| {x['id']} | {x['label']} | {x['expected']} | {'oui' if x['detected'] else 'non'} | {rb} |")
    pct = lambda v: f"{v * 100:.0f} %"  # noqa: E731
    lat = lambda v: f"{v:.2f} s" if v is not None else "-"  # noqa: E731
    lines += ["",
              f"- Taux de détection : **{pct(r['detection_rate'])}**",
              f"- Taux de faux positifs : **{pct(r['false_positive_rate'])}**",
              f"- Attaques bloquées au rejeu : **{pct(r['block_rate'])}**",
              f"- Actions légitimes toujours permises : **{pct(r['legit_preserved_rate'] or 0)}**",
              f"- Latence détection -> politique appliquée : médiane **{lat(r['latency_median_s'])}**, "
              f"max {lat(r['latency_max_s'])}"]
    return "\n".join(lines)


if __name__ == "__main__":
    scen = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
    evts = json.load(open(sys.argv[2]))
    print(report(evaluate(scen, evts)))
