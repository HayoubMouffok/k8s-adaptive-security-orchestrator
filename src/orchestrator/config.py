"""Configuration lue depuis les variables d'environnement."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_list(name: str, default: str) -> list[str]:
    return [x.strip() for x in os.getenv(name, default).split(",") if x.strip()]


@dataclass
class Config:
    # Namespaces surveillés : une alerte hors de ces namespaces est ignorée
    # (évite de bloquer kube-system ou les outils de sécurité eux-mêmes).
    watched_namespaces: list[str] = field(
        default_factory=lambda: _env_list("WATCHED_NAMESPACES", "demo")
    )
    # Priorités Falco qui déclenchent un blocage automatique.
    # En dessous, la politique est créée en mode Audit et attend une validation humaine.
    auto_block_priorities: list[str] = field(
        default_factory=lambda: _env_list("AUTO_BLOCK_PRIORITIES", "Emergency,Alert,Critical")
    )
    # Durée de vie d'une politique non confirmée (secondes). 0 = pas d'expiration.
    policy_ttl_seconds: int = int(os.getenv("POLICY_TTL_SECONDS", "3600"))
    # Mode "dry-run" : génère les politiques sans les appliquer (tests, démo locale).
    dry_run: bool = os.getenv("DRY_RUN", "false").lower() == "true"
    # Webhook optionnel (Slack, Mattermost...) pour demander une validation humaine.
    approval_webhook_url: str = os.getenv("APPROVAL_WEBHOOK_URL", "")


PRIORITY_ORDER = [
    "Debug", "Informational", "Notice", "Warning", "Error", "Critical", "Alert", "Emergency",
]
