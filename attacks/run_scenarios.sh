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

pkill -f "port-forward svc/orchestrator 18080" 2>/dev/null  # ancien tunnel éventuellement resté ouvert
kubectl -n security-orchestrator rollout status deploy/orchestrator --timeout=120s >/dev/null
kubectl -n security-orchestrator port-forward svc/orchestrator 18080:8080 >/dev/null 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null' EXIT
for _ in $(seq 30); do curl -sf "$API/healthz" >/dev/null && break; sleep 1; done
curl -sf "$API/healthz" >/dev/null || { echo "API de l'orchestrateur injoignable"; exit 1; }

log() {  # id, label (malicious|benign), type attendu, résultat du 2e essai
  printf '{"id":"%s","label":"%s","expected":"%s","start":"%s","replay_blocked":%s}\n' \
    "$1" "$2" "$3" "$4" "$5" >> "$OUT"
}
now() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
run() { kubectl -n "$NS" exec "$POD" "$@" >/dev/null 2>&1; }
# Shell avec un vrai terminal (la règle Falco « Terminal shell in container » exige un TTY) :
# « script » fournit un pseudo-terminal à kubectl exec -it, même lancé depuis un script.
# Le shell est lancé par un processus du conteneur (env), comme lors d'une RCE : AppArmor ne contrôle
# pas le tout premier binaire d'un « kubectl exec » (la transition de profil a lieu à cet exec),
# ce cas-là relève du RBAC sur pods/exec (voir README, limites).
shell() { script -qec "kubectl -n $NS exec -it $POD -- env sh -c 'id'" /dev/null </dev/null >/dev/null 2>&1; }

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

echo "== M4 (T1528) : vol du jeton du compte de service"
T=$(now); run -- cat /var/run/secrets/kubernetes.io/serviceaccount/token; sleep 8
if run -- cat /var/run/secrets/kubernetes.io/serviceaccount/token; then R=false; else R=true; fi
log M4 malicious token_theft "$T" "$R"
echo "   rejeu bloqué : $R"

echo "== B3 (légitime) : écriture d'un fichier temporaire par l'application"
T=$(now); run -- sh -c 'echo cache > /tmp/app-cache && cat /tmp/app-cache'; sleep 5
if run -- sh -c 'echo cache > /tmp/app-cache'; then R=false; else R=true; fi
log B3 benign none "$T" "$R"
echo "   action légitime toujours autorisée : $([ "$R" = false ] && echo oui || echo NON)"

echo "== M5 (T1105) : exécution d'un outil déposé dans /tmp"
T=$(now); run -- sh -c 'cp /usr/bin/id /tmp/scan && /tmp/scan'; sleep 8
if run -- sh -c 'cp /usr/bin/id /tmp/scan2 && /tmp/scan2'; then R=false; else R=true; fi
log M5 malicious untrusted_binary "$T" "$R"
echo "   rejeu bloqué : $R"

echo "== M6 (T1554) : altération d'un répertoire de binaires"
T=$(now); run -- touch /usr/bin/backdoor; sleep 8
if run -- touch /usr/bin/backdoor2; then R=false; else R=true; fi
log M6 malicious binary_tampering "$T" "$R"
echo "   rejeu bloqué : $R"

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

echo "== B4 (légitime) : le service web répond toujours après toutes les politiques"
T=$(now); run -- curl -s -m 5 -o /dev/null http://web.demo.svc.cluster.local; sleep 5
if run -- curl -sf -m 5 -o /dev/null http://web.demo.svc.cluster.local && run -- nginx -t; then R=false; else R=true; fi
log B4 benign none "$T" "$R"
echo "   service toujours fonctionnel : $([ "$R" = false ] && echo oui || echo NON)"

curl -s "$API/events" > results/events.json
curl -s "$API/metrics" > results/metrics.txt
python3 evaluate.py results/scenarios.jsonl results/events.json | tee results/report.md
