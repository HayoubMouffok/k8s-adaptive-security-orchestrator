"""Classification des alertes Falco en types de menace, avec correspondance MITRE ATT&CK.

Entrée : le JSON envoyé par Falcosidekick (webhook), de la forme :
    {"rule": "...", "priority": "Critical", "time": "2026-...Z", "output": "...",
     "output_fields": {"k8s.ns.name": "...", "k8s.pod.name": "...", "proc.name": "...",
                       "proc.exepath": "...", "fd.name": "...", ...},
     "tags": ["mitre_execution", "T1059", ...]}
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

# Type de menace -> technique MITRE ATT&CK de référence
MITRE = {
    "shell_execution": ("T1059", "Command and Scripting Interpreter"),
    "sensitive_file_access": ("T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow"),
    "network_activity": ("T1071", "Application Layer Protocol"),
    "privilege_escalation": ("T1611", "Escape to Host"),
    "token_theft": ("T1528", "Steal Application Access Token"),
    "untrusted_binary": ("T1105", "Ingress Tool Transfer"),
    "binary_tampering": ("T1554", "Compromise Host Software Binary"),
    "unknown": ("", "Non classé"),
}

SHELLS = {"bash", "sh", "zsh", "dash", "ash", "ksh"}
SENSITIVE_PREFIXES = ("/etc/shadow", "/etc/sudoers", "/root/.ssh", "/etc/kubernetes")
SA_TOKEN_DIR = "/secrets/kubernetes.io/serviceaccount"
TMP_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/")


@dataclass
class ThreatEvent:
    threat_type: str
    mitre_id: str
    mitre_name: str
    priority: str
    rule: str
    namespace: str
    pod: str
    process: str
    exe_path: str
    file_path: str
    remote_ip: str
    alert_time: datetime
    raw: dict = field(repr=False, default_factory=dict)


def _parse_time(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    # Falco envoie des timestamps RFC3339 en nanosecondes : on tronque aux microsecondes.
    v = value.rstrip("Z")
    if "." in v:
        head, frac = v.split(".", 1)
        v = f"{head}.{frac[:6]}"
    try:
        return datetime.fromisoformat(v).replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def classify(alert: dict) -> ThreatEvent:
    rule = alert.get("rule", "")
    rl = rule.lower()
    f = alert.get("output_fields", {}) or {}
    tags = [str(t).lower() for t in alert.get("tags", []) or []]
    proc = str(f.get("proc.name") or "").lower()
    exe = str(f.get("proc.exepath") or f.get("proc.exe") or "")
    fd = str(f.get("fd.name") or "")

    if "privilege" in rl or "escape" in rl or "mitre_privilege_escalation" in tags:
        t = "privilege_escalation"
    elif SA_TOKEN_DIR in fd or "service account token" in rl:
        t = "token_theft"
    elif exe.startswith(TMP_DIRS) or "drop and execute" in rl or "executed from temporary" in rl:
        t = "untrusted_binary"
    elif "binary dir" in rl:
        t = "binary_tampering"
    elif fd.startswith(SENSITIVE_PREFIXES) or "sensitive file" in rl:
        t = "sensitive_file_access"
    elif "shell" in rl or proc in SHELLS or "mitre_execution" in tags:
        t = "shell_execution"
    elif "connection" in rl or "network" in rl or "mitre_command_and_control" in tags:
        t = "network_activity"
    else:
        t = "unknown"

    mitre_id, mitre_name = MITRE[t]
    # Si Falco fournit déjà un identifiant de technique dans les tags, on le privilégie.
    for tag in alert.get("tags", []) or []:
        if str(tag).startswith("T1"):
            mitre_id = str(tag)
            break

    remote = str(f.get("fd.sip") or f.get("fd.rip") or "")
    if "->" in fd and not remote:
        remote = fd.split("->", 1)[1].rsplit(":", 1)[0]

    return ThreatEvent(
        threat_type=t,
        mitre_id=mitre_id,
        mitre_name=mitre_name,
        priority=alert.get("priority", "Notice"),
        rule=rule,
        namespace=str(f.get("k8s.ns.name") or ""),
        pod=str(f.get("k8s.pod.name") or ""),
        process=proc,
        exe_path=exe,
        file_path=fd if t == "sensitive_file_access" else "",
        remote_ip=remote,
        alert_time=_parse_time(alert.get("time")),
        raw=alert,
    )
