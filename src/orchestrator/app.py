"""API de l'orchestrateur : reçoit les alertes Falco (via Falcosidekick) et applique la réponse.

Endpoints :
  POST /falco                         alerte Falcosidekick (webhook)
  POST /approve/<namespace>/<name>    un humain confirme : la politique passe de Audit à Block
  POST /reject/<namespace>/<name>     un humain infirme : politique supprimée, faux positif compté
  GET  /events                        historique des événements traités (pour l'évaluation)
  GET  /metrics                       métriques Prometheus
  GET  /healthz
"""
from __future__ import annotations

import json
import logging
import threading
import time
import urllib.request
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, request
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

from .classifier import classify
from .config import Config
from .policy import build_policy

log = logging.getLogger("orchestrator")

ALERTS = Counter("orchestrator_alerts_total", "Alertes reçues", ["threat_type", "priority"])
POLICIES = Counter("orchestrator_policies_applied_total", "Politiques appliquées", ["kind", "mode"])
FALSE_POS = Counter("orchestrator_false_positives_total", "Alertes infirmées par un humain", ["threat_type"])
EXPIRED = Counter("orchestrator_policies_expired_total", "Politiques audit expirées sans validation")
PENDING = Gauge("orchestrator_pending_approvals", "Politiques en attente de validation humaine")
LATENCY = Histogram(
    "orchestrator_response_seconds",
    "Délai entre l'événement détecté par Falco et l'application de la politique",
    buckets=(0.1, 0.25, 0.5, 1, 2, 5, 10, 30),
)


def create_app(kube=None, cfg: Config | None = None, start_reaper: bool = True) -> Flask:
    cfg = cfg or Config()
    if kube is None and not cfg.dry_run:
        from .k8s import KubeClient

        kube = KubeClient()
    app = Flask(__name__)
    events: list[dict] = []
    pending: dict[str, dict] = {}  # "ns/name" -> {"event", "labels"}
    lock = threading.Lock()

    def notify(text: str) -> None:
        if not cfg.approval_webhook_url:
            return
        try:
            req = urllib.request.Request(
                cfg.approval_webhook_url, data=json.dumps({"text": text}).encode(),
                headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:  # noqa: BLE001 - la notification ne doit jamais bloquer la réponse
            log.warning("notification échouée : %s", e)

    @app.post("/falco")
    def falco():
        alert = request.get_json(force=True, silent=True) or {}
        ev = classify(alert)
        ALERTS.labels(ev.threat_type, ev.priority).inc()
        record = {
            "received_at": datetime.now(timezone.utc).isoformat(),
            "alert_time": ev.alert_time.isoformat(),
            "rule": ev.rule, "priority": ev.priority,
            "threat_type": ev.threat_type, "mitre": ev.mitre_id,
            "namespace": ev.namespace, "pod": ev.pod, "action": "ignored",
        }

        if ev.namespace not in cfg.watched_namespaces or not ev.pod:
            record["reason"] = "namespace non surveillé"
            events.append(record)
            return jsonify(record), 200

        block = ev.priority in cfg.auto_block_priorities
        try:
            labels = kube.pod_labels(ev.namespace, ev.pod) if kube else {"app": ev.pod}
            manifest = build_policy(ev, labels, block=block, ttl=0 if block else cfg.policy_ttl_seconds)
        except Exception as e:  # noqa: BLE001 - erreur API ou pod sans label
            record.update(action="error", reason=str(e))
            events.append(record)
            log.error("génération impossible : %s", e)
            return jsonify(record), 200

        if manifest is None:
            record["reason"] = "pas de réponse automatique pour ce type"
            events.append(record)
            return jsonify(record), 200

        status = "dry-run" if cfg.dry_run else kube.apply(manifest)
        latency = (datetime.now(timezone.utc) - ev.alert_time).total_seconds()
        LATENCY.observe(max(latency, 0))
        mode = "block" if block else "audit"
        POLICIES.labels(manifest["kind"], mode).inc()
        name = manifest["metadata"]["name"]
        record.update(action=mode, policy=name, kind=manifest["kind"],
                      status=status, latency_s=round(latency, 3))
        events.append(record)

        if not block:
            with lock:
                pending[f"{ev.namespace}/{name}"] = {"event": ev, "labels": labels}
                PENDING.set(len(pending))
            notify(f"[{ev.priority}] {ev.rule} sur {ev.namespace}/{ev.pod} ({ev.mitre_id}). "
                   f"Politique {name} en audit. Valider : POST /approve/{ev.namespace}/{name} - "
                   f"infirmer : POST /reject/{ev.namespace}/{name}")
        log.info("%s %s/%s -> %s %s (%.3fs)", ev.threat_type, ev.namespace, ev.pod, mode, name, latency)
        return jsonify(record), 200

    @app.post("/approve/<ns>/<name>")
    def approve(ns, name):
        with lock:
            item = pending.pop(f"{ns}/{name}", None)
            PENDING.set(len(pending))
        if not item:
            return jsonify({"error": "aucune politique en attente"}), 404
        manifest = build_policy(item["event"], item["labels"], block=True, ttl=0)
        if manifest and not cfg.dry_run:
            kube.apply(manifest)
        POLICIES.labels(manifest["kind"] if manifest else "none", "block").inc()
        return jsonify({"policy": name, "mode": "block"}), 200

    @app.post("/reject/<ns>/<name>")
    def reject(ns, name):
        with lock:
            item = pending.pop(f"{ns}/{name}", None)
            PENDING.set(len(pending))
        if not item:
            return jsonify({"error": "aucune politique en attente"}), 404
        if not cfg.dry_run:
            kube.delete("KubeArmorPolicy", ns, name)
        FALSE_POS.labels(item["event"].threat_type).inc()
        return jsonify({"policy": name, "deleted": True, "false_positive": True}), 200

    @app.get("/events")
    def get_events():
        return jsonify(events)

    @app.get("/metrics")
    def metrics():
        return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

    @app.get("/healthz")
    def healthz():
        return "ok", 200

    def reaper():
        while True:
            time.sleep(30)
            try:
                for kind, ns, name in kube.expired(cfg.watched_namespaces):
                    kube.delete(kind, ns, name)
                    with lock:
                        pending.pop(f"{ns}/{name}", None)
                        PENDING.set(len(pending))
                    EXPIRED.inc()
                    log.info("politique expirée supprimée : %s/%s", ns, name)
            except Exception as e:  # noqa: BLE001 - le nettoyage ne doit pas tuer le thread
                log.warning("nettoyage TTL : %s", e)

    if start_reaper and kube is not None and cfg.policy_ttl_seconds:
        threading.Thread(target=reaper, daemon=True).start()

    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    create_app().run(host="0.0.0.0", port=8080)


if __name__ == "__main__":
    main()
