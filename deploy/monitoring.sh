#!/usr/bin/env bash
# Déploie Prometheus + Grafana et charge le tableau de bord. Grafana : http://<IP du nœud>:30300
set -euo pipefail
cd "$(dirname "$0")/.."
kubectl apply -f deploy/monitoring.yaml
kubectl -n monitoring create configmap grafana-dashboard --from-file=deploy/grafana/dashboard.json \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n monitoring rollout restart deploy/grafana >/dev/null
kubectl -n monitoring rollout status deploy/prometheus --timeout=300s
kubectl -n monitoring rollout status deploy/grafana --timeout=300s
echo "Grafana : http://$(hostname -I | awk '{print $1}'):30300"
