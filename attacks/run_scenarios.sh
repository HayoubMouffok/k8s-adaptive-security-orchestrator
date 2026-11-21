#!/usr/bin/env bash
# Rejoue des actions légitimes et des attaques sur le pod de démo, puis mesure :
#   - taux de détection, faux positifs, latence détection -> politique appliquée
#   - efficacité du blocage (l'attaque rejouée après la politique doit échouer)
# Chaque attaque correspond à une technique MITRE ATT&CK.
# Usage : ./attacks/run_scenarios.sh   (KUBECONFIG pointant vers le cluster)
set -uo pipefail
cd "$(dirname "$0")" || exit 1
mkdir -p results
OUT=results/scenarios.jsonl
: > "$OUT"
POD="deploy/web"
NS=demo
API=http://127.0.0.1:18080

echo "== Préparation : suppression des politiques créées lors des essais précédents"
kubectl -n "$NS" delete kubearmorpolicies,networkpolicies \
  -l app.kubernetes.io/managed-by=security-orchestrator --ignore-not-found >/dev/null
sleep 5

kubectl -n security-orchestrator port-forward svc/orchestrator 18080:8080 >/dev/null 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null' EXIT
sleep 3

log() {  # id, label (malicious|benign), type attendu, résultat du 2e essai
  printf '{"id":"%s","label":"%s","expected":"%s","start":"%s","replay_blocked":%s}\n' \
    "$1" "$2" "$3" "$4" "$5" >> "$OUT"
}
now() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
run() { kubectl -n "$NS" exec "$POD" "$@" >/dev/null 2>&1; }
# Shell avec un vrai terminal (la règle Falco « Terminal shell in container » exige un TTY) :
# « script » fournit un pseudo-terminal à kubectl exec -it, même lancé depuis un script.
shell() { script -qec "kubectl -n $NS exec -it $POD -- sh -c 'id'" /dev/null </dev/null >/dev/null 2>&1; }

echo "== B1 (légitime) : lecture de la configuration nginx"
T=$(now); run -- nginx -t; run -- ls /usr/share/nginx/html; sleep 5
log B1 benign none "$T" null

echo "== M1 (T1003.008) : lecture de /etc/shadow"
T=$(now); run -- cat /etc/shadow; sleep 8
if run -- cat /etc/shadow; then R=false; else R=true; fi
log M1 malicious sensitive_file_access "$T" "$R"
echo "   rejeu bloqué : $R"

echo "== M2 (T1071) : connexion vers le serveur C2 de laboratoire (1.1.1.1)"
T=$(now); run -- curl -s -m 5 -o /dev/null https://1.1.1.1; sleep 8
if run -- curl -s -m 5 -o /dev/null https://1.1.1.1; then R=false; else R=true; fi
log M2 malicious network_activity "$T" "$R"
echo "   rejeu bloqué : $R"

echo "== B2 (légitime) : appel HTTP interne au service web"
T=$(now); run -- curl -s -m 5 -o /dev/null http://web.demo.svc.cluster.local; sleep 5
if run -- curl -s -m 5 -o /dev/null http://web.demo.svc.cluster.local; then R=false; else R=true; fi
log B2 benign none "$T" "$R"
echo "   trafic légitime toujours autorisé : $([ "$R" = false ] && echo oui || echo NON)"

echo "== M3 (T1059) : shell interactif dans le conteneur (priorité Notice -> validation humaine)"
T=$(now); shell; sleep 8
NAME=$(curl -s "$API/events" | python3 -c \
  "import json,sys;e=[x for x in json.load(sys.stdin) if x.get('threat_type')=='shell_execution' and x.get('action')=='audit'];print(e[-1]['policy'] if e else '')")
if [ -n "$NAME" ]; then
  echo "   politique en audit : $NAME -> validation humaine simulée"
  curl -s -X POST "$API/approve/$NS/$NAME" >/dev/null; sleep 10
fi
if shell; then R=false; else R=true; fi
log M3 malicious shell_execution "$T" "$R"
echo "   rejeu bloqué : $R"

curl -s "$API/events" > results/events.json
curl -s "$API/metrics" > results/metrics.txt
python3 evaluate.py results/scenarios.jsonl results/events.json | tee results/report.md
