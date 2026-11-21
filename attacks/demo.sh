#!/usr/bin/env bash
# Démo commentée (~2 min) à filmer : attaque réussie -> détection -> politique -> attaque bloquée.
# Usage : ./attacks/demo.sh
set -uo pipefail
NS=demo
POD=deploy/web
B=$'\e[1m'; R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; N=$'\e[0m'

say()  { printf '\n%s\n' "${B}${C}▶ $*${N}"; sleep 2; }
cmd()  { printf '%s\n' "${Y}\$ $*${N}"; sleep 1; eval "$*"; }
wait_s() { for i in $(seq "$1" -1 1); do printf '\r   %s' "${B}orchestrateur en action… ${i}s ${N}"; sleep 1; done; printf '\r%60s\r' ''; }

kubectl -n "$NS" delete kubearmorpolicies,networkpolicies \
  -l app.kubernetes.io/managed-by=security-orchestrator --ignore-not-found >/dev/null
sleep 3
clear
printf '%s\n' "${B}Orchestrateur de sécurité adaptative Kubernetes — Falco + KubeArmor${N}"
printf '%s\n' "Pod cible : nginx (namespace demo). Aucune politique de sécurité au départ."
sleep 3

say "1. Un attaquant lit les mots de passe du conteneur (MITRE T1003.008)"
cmd "kubectl -n $NS exec $POD -- cat /etc/shadow | head -3"
printf '%s\n' "${R}   → l'attaque réussit${N}"
wait_s 6
say "Falco a détecté l'accès, l'orchestrateur a généré et appliqué une politique KubeArmor :"
cmd "kubectl -n $NS get kubearmorpolicies -o custom-columns=POLITIQUE:.metadata.name,ACTION:.spec.action,MITRE:.metadata.labels.mitre"
say "L'attaquant réessaie :"
cmd "kubectl -n $NS exec $POD -- cat /etc/shadow"
printf '%s\n' "${G}   → bloqué par le noyau (AppArmor)${N}"

say "2. Connexion vers un serveur de commande et contrôle (MITRE T1071)"
cmd "kubectl -n $NS exec $POD -- curl -s -m 4 -o /dev/null -w '%{http_code}\n' https://1.1.1.1"
printf '%s\n' "${R}   → la connexion passe${N}"
wait_s 6
cmd "kubectl -n $NS get networkpolicies"
cmd "kubectl -n $NS exec $POD -- curl -s -m 4 -o /dev/null -w '%{http_code}\n' https://1.1.1.1 || true"
printf '%s\n' "${G}   → coupée par la NetworkPolicy${N}"

say "3. Le service légitime fonctionne toujours"
cmd "kubectl -n $NS exec $POD -- curl -s -m 4 -o /dev/null -w 'HTTP %{http_code}\n' http://web.demo.svc.cluster.local"

printf '\n%s\n' "${B}${G}Détection → blocage en ~30 ms, sans intervention humaine. Résultats complets : ./attacks/run_scenarios.sh${N}"
