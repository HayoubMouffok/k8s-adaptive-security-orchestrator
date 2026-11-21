"""Génération des politiques de réponse à partir d'un ThreatEvent.

- Menaces processus / fichier -> KubeArmorPolicy (blocage au niveau du noyau via LSM),
  ciblée sur le pod attaqué grâce à ses labels (et non plus sur tout un namespace).
- Activité réseau -> NetworkPolicy Kubernetes qui coupe le trafic sortant vers l'IP suspecte.
"""
from __future__ import annotations

import hashlib
import json
import time

from .classifier import ThreatEvent

SEVERITY = {"Emergency": 10, "Alert": 9, "Critical": 8, "Error": 6, "Warning": 5}
SA_TOKEN_DIRS = ["/run/secrets/kubernetes.io/serviceaccount/", "/var/run/secrets/kubernetes.io/serviceaccount/"]
TMP_DIRS = ["/tmp/", "/dev/shm/", "/var/tmp/"]
BIN_DIRS = ["/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/"]
SHELL_PATHS = ["/bin/sh", "/bin/bash", "/bin/dash", "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/dash"]

# Labels ajoutés par Kubernetes / les contrôleurs, inutiles pour cibler un pod.
_IGNORED_LABELS = {"pod-template-hash", "controller-revision-hash", "pod-template-generation"}


def _name(event: ThreatEvent) -> str:
    h = hashlib.sha1(f"{event.namespace}/{event.pod}/{event.rule}".encode()).hexdigest()[:8]
    return f"auto-{event.threat_type.replace('_', '-')}-{h}"


def _selector_labels(pod_labels: dict[str, str]) -> dict[str, str]:
    labels = {k: v for k, v in (pod_labels or {}).items() if k not in _IGNORED_LABELS}
    if not labels:
        raise ValueError("le pod n'a aucun label exploitable pour le cibler")
    return labels


def _metadata(event: ThreatEvent, mode: str, ttl: int) -> dict:
    now = int(time.time())
    return {
        "name": _name(event),
        "namespace": event.namespace,
        "labels": {
            "app.kubernetes.io/managed-by": "security-orchestrator",
            "threat-type": event.threat_type.replace("_", "-"),
            "mitre": event.mitre_id.replace(".", "-") or "none",
            "mode": mode,
        },
        "annotations": {
            "orchestrator/rule": event.rule,
            "orchestrator/pod": event.pod,
            "orchestrator/created-at": str(now),
            "orchestrator/expires-at": str(now + ttl) if ttl else "never",
        },
    }


def build_policy(event: ThreatEvent, pod_labels: dict[str, str], block: bool,
                 ttl: int) -> dict | None:
    """Retourne le manifeste à appliquer, ou None si aucune réponse automatique n'est prévue."""
    mode = "block" if block else "audit"
    action = "Block" if block else "Audit"
    selector = _selector_labels(pod_labels)
    meta = _metadata(event, mode, ttl)

    if event.threat_type == "network_activity":
        if not event.remote_ip:
            return None
        if not block:
            # Une NetworkPolicy n'a pas de mode audit : sans validation, on ne coupe rien.
            return None
        return {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": meta,
            "spec": {
                "podSelector": {"matchLabels": selector},
                "policyTypes": ["Egress"],
                "egress": [{"to": [{"ipBlock": {"cidr": "0.0.0.0/0",
                                                "except": [f"{event.remote_ip}/32"]}}]}],
            },
        }

    spec: dict = {
        "severity": SEVERITY.get(event.priority, 5),
        "message": f"{event.mitre_id} {event.mitre_name} - {event.rule}",
        "tags": ["MITRE", event.mitre_id] if event.mitre_id else ["orchestrator"],
        "selector": {"matchLabels": selector},
        "action": action,
    }
    if event.threat_type == "shell_execution":
        paths = sorted(set(SHELL_PATHS + ([event.exe_path] if event.exe_path.startswith("/") else [])))
        spec["process"] = {"matchPaths": [{"path": p} for p in paths]}
    elif event.threat_type == "sensitive_file_access":
        spec["file"] = {"matchPaths": [{"path": event.file_path or "/etc/shadow"}]}
    elif event.threat_type == "token_theft":
        spec["file"] = {"matchDirectories": [{"dir": d, "recursive": True} for d in SA_TOKEN_DIRS]}
    elif event.threat_type == "untrusted_binary":
        # Exécution interdite depuis les répertoires temporaires ; l'écriture y reste permise.
        spec["process"] = {"matchDirectories": [{"dir": d, "recursive": True} for d in TMP_DIRS]}
    elif event.threat_type == "binary_tampering":
        # Lecture seule : les binaires restent exécutables mais ne peuvent plus être modifiés.
        spec["file"] = {"matchDirectories": [{"dir": d, "recursive": True, "readOnly": True}
                                             for d in BIN_DIRS]}
    elif event.threat_type == "privilege_escalation" and event.exe_path.startswith("/"):
        spec["process"] = {"matchPaths": [{"path": event.exe_path}]}
    else:
        return None

    return {
        "apiVersion": "security.kubearmor.com/v1",
        "kind": "KubeArmorPolicy",
        "metadata": meta,
        "spec": spec,
    }


def build_exec_guard(event: ThreatEvent, pod_labels: dict[str, str]) -> dict | None:
    """Seconde couche pour les shells : une NamespacedValidatingPolicy Kyverno (CEL) refuse tout
    « kubectl exec » vers les pods visés, au niveau de l'API Kubernetes. AppArmor ne contrôle pas le
    premier binaire d'un exec (la transition de profil a lieu à cet exec), cette règle comble ce trou."""
    if event.threat_type != "shell_execution":
        return None
    selector = _selector_labels(pod_labels)
    meta = _metadata(event, "block", 0)
    meta["name"] = meta["name"].replace("auto-shell-execution", "auto-deny-exec")
    targeted = " && ".join(
        f"variables.pod.metadata.?labels[{json.dumps(k)}].orValue('') == {json.dumps(v)}"
        for k, v in sorted(selector.items()))
    return {
        "apiVersion": "policies.kyverno.io/v1",
        "kind": "NamespacedValidatingPolicy",
        "metadata": meta,
        "spec": {
            "validationActions": ["Deny"],
            "matchConstraints": {"resourceRules": [{
                "apiGroups": [""], "apiVersions": ["v1"],
                "operations": ["CONNECT"], "resources": ["pods/exec"]}]},
            "variables": [{"name": "pod",
                           "expression": 'resource.Get("v1", "pods", request.namespace, request.name)'}],
            "validations": [{
                "expression": f"!({targeted})",
                "message": f"{event.mitre_id} : exec interdit sur ce pod après détection d'un shell "
                           f"({meta['annotations']['orchestrator/rule']})",
            }],
        },
    }
