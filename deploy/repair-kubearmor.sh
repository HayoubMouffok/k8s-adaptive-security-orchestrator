#!/usr/bin/env bash
# Remet KubeArmor d'aplomb après un redémarrage de la VM.
# Symptôme : le DaemonSet kubearmor redémarre en boucle (« Containerd socket file is not accessible »)
# et les nouveaux pods restent en CreateContainerError (« apparmor profile not found »), car KubeArmor
# leur attribue un profil qu'il n'a pas pu charger. Cause : au démarrage, containerd recrée le socket
# NRI (/run/nri) que la détection automatique de KubeArmor choisit à tort.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
export KUBECONFIG=${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}

echo "== Désinstallation de KubeArmor"
kubectl delete kubearmorconfig --all -A --ignore-not-found --timeout=60s || true
helm -n kubearmor uninstall kubearmor-operator --wait || true
kubectl delete ns kubearmor --ignore-not-found --timeout=120s || true
# shellcheck disable=SC2016  # gabarit Go, pas une expansion shell
for l in $(kubectl get nodes -o go-template='{{range .items}}{{range $k,$v := .metadata.labels}}{{$k}}{{"\n"}}{{end}}{{end}}' | grep '^kubearmor.io/' | sort -u); do
  kubectl label nodes --all "$l-" >/dev/null
done
sudo rm -rf /run/nri

echo "== Réinstallation"
helm upgrade --install kubearmor-operator kubearmor/kubearmor-operator -n kubearmor --create-namespace --wait
kubectl apply -f https://raw.githubusercontent.com/kubearmor/KubeArmor/main/pkg/KubeArmorOperator/config/samples/sample-config.yml
sleep 20
kubectl -n kubearmor rollout status ds -l kubearmor-app=kubearmor --timeout=300s || true

echo "== Redémarrage des pods créés pendant la panne"
for ns in demo security-orchestrator kyverno monitoring falco; do
  kubectl -n "$ns" delete pods --field-selector=status.phase!=Running --ignore-not-found >/dev/null 2>&1 || true
done
kubectl -n demo rollout restart deploy/web
kubectl -n demo rollout status deploy/web --timeout=120s
kubectl get pods -A | grep -v -e Running -e Completed || echo "Tous les pods tournent."
