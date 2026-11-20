#!/usr/bin/env bash
# Installe la plateforme complète sur une VM Linux (Ubuntu 22.04/24.04 recommandé, 4 Go RAM, 2 vCPU).
#   k3s (Kubernetes léger) + KubeArmor (blocage via AppArmor/BPF-LSM) + Falco + Falcosidekick
#   + l'orchestrateur + une application de démonstration.
# Usage : sudo ./deploy/install.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== 1/6 Vérification du LSM (nécessaire pour que KubeArmor BLOQUE, et pas seulement audite)"
LSM=$(cat /sys/kernel/security/lsm 2>/dev/null || true)
echo "LSM actifs : ${LSM:-inconnu}"
if ! grep -qE 'apparmor|bpf' <<<"$LSM"; then
  echo "ERREUR : ni AppArmor ni BPF-LSM n'est actif. KubeArmor ne pourra qu'auditer."
  echo "Sur Ubuntu : sudo apt install apparmor && reboot."
  exit 1
fi

echo "== 2/6 k3s"
if ! command -v k3s >/dev/null; then
  curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--write-kubeconfig-mode 644" sh -
fi
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
kubectl wait --for=condition=Ready node --all --timeout=180s

echo "== 3/6 Helm"
command -v helm >/dev/null || curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

echo "== 4/6 KubeArmor"
helm repo add kubearmor https://kubearmor.github.io/charts >/dev/null
helm repo update >/dev/null
helm upgrade --install kubearmor-operator kubearmor/kubearmor-operator -n kubearmor --create-namespace --wait
kubectl apply -f https://raw.githubusercontent.com/kubearmor/KubeArmor/main/pkg/KubeArmorOperator/config/samples/sample-config.yml
kubectl -n kubearmor rollout status ds -l kubearmor-app=kubearmor --timeout=300s || true

echo "== 5/6 Orchestrateur + application de démo"
command -v docker >/dev/null || { apt-get update -qq && apt-get install -y -qq docker.io; }
docker build -t security-orchestrator:2.0.0 .
docker save security-orchestrator:2.0.0 | k3s ctr images import -
kubectl apply -f deploy/orchestrator.yaml -f deploy/demo-app.yaml
kubectl -n security-orchestrator rollout status deploy/orchestrator --timeout=120s
kubectl -n demo rollout status deploy/web --timeout=120s

echo "== 6/6 Falco + Falcosidekick (webhook vers l'orchestrateur)"
# Le socket containerd de k3s (/run/k3s/containerd/containerd.sock) fait partie des sockets
# surveillés par défaut par le chart : pas de réglage supplémentaire nécessaire.
helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null
helm repo update >/dev/null
helm upgrade --install falco falcosecurity/falco -n falco --create-namespace \
  -f deploy/falco-values.yaml --wait --timeout 10m

echo
echo "Plateforme prête. Lancer les scénarios : ./attacks/run_scenarios.sh"
