# Orchestration dynamique de politiques de sécurité Kubernetes

Projet de mémoire de **Master Réseaux et Objets Connectés (CNAM, 2025)** – Hayoub Mouffok.

Prototype qui détecte un comportement suspect dans un cluster Kubernetes et **génère puis applique automatiquement une politique KubeArmor** adaptée, sans intervention humaine.

## Architecture

Boucle **Détection → Décision → Action** :

1. **Détection** : alertes de sécurité (Falco ou simulateur intégré).
2. **Décision** : classification de la menace (`file_access`, `shell_execution`, `network_activity`).
3. **Action** : génération d'une `KubeArmorClusterPolicy` contextualisée et application via l'API Kubernetes.

Un orchestrateur Python expose une API REST (Flask) : `POST /simulate` pour déclencher un scénario d'attaque, `GET /stats` pour les métriques.

## Résultats

| Indicateur | Valeur |
|---|---|
| Politiques générées | 6 (3 types de menaces) |
| Taux de réussite de génération | 100 % |
| Temps de génération par politique | 680 à 910 ms |
| Chaîne complète détection → application | ~0,9 s (contre ~50 min en traitement manuel estimé) |

## Stack

Kubernetes (Minikube), KubeArmor (déployé via Helm), Falco, Kyverno, OPA, Python, Flask, API Kubernetes, Linux.

## Contenu du dépôt

- `src/orchestrator_excerpts.py` : extraits du code de l'orchestrateur (classification, API REST, simulateur).
- `policies/` : politiques KubeArmor générées automatiquement pendant les tests.

> Les extraits proviennent du mémoire. Limites identifiées : l'application effective des politiques par KubeArmor sous Minikube et l'intégration Falco ont demandé des ajustements de configuration (runtime containerd) ; un cluster multi-nœuds est la prochaine étape.
