"""Accès à l'API Kubernetes (isolé pour pouvoir être remplacé par un faux client en test)."""
from __future__ import annotations

import time

KA_GROUP, KA_VERSION, KA_PLURAL = "security.kubearmor.com", "v1", "kubearmorpolicies"
KY_GROUP, KY_VERSION, KY_PLURAL = "kyverno.io", "v1", "policies"
CRD = {"KubeArmorPolicy": (KA_GROUP, KA_VERSION, KA_PLURAL), "Policy": (KY_GROUP, KY_VERSION, KY_PLURAL)}
MANAGED = "app.kubernetes.io/managed-by=security-orchestrator"


class KubeClient:
    def __init__(self):
        from kubernetes import client, config

        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        self.core = client.CoreV1Api()
        self.custom = client.CustomObjectsApi()
        self.net = client.NetworkingV1Api()
        self._ApiException = client.exceptions.ApiException

    def pod_labels(self, namespace: str, pod: str) -> dict[str, str]:
        return self.core.read_namespaced_pod(pod, namespace).metadata.labels or {}

    def apply(self, manifest: dict) -> str:
        """Crée la politique, ou la remplace si elle existe déjà. Retourne 'created' ou 'updated'."""
        ns, name = manifest["metadata"]["namespace"], manifest["metadata"]["name"]
        kind = manifest["kind"]
        try:
            if kind in CRD:
                self.custom.create_namespaced_custom_object(*CRD[kind][:2], ns, CRD[kind][2], manifest)
            else:
                self.net.create_namespaced_network_policy(ns, manifest)
            return "created"
        except self._ApiException as e:
            if e.status != 409:
                raise
        if kind in CRD:
            self.custom.patch_namespaced_custom_object(*CRD[kind][:2], ns, CRD[kind][2], name, manifest)
        else:
            self.net.patch_namespaced_network_policy(name, ns, manifest)
        return "updated"

    def delete(self, kind: str, namespace: str, name: str) -> None:
        try:
            if kind in CRD:
                self.custom.delete_namespaced_custom_object(*CRD[kind][:2], namespace, CRD[kind][2], name)
            else:
                self.net.delete_namespaced_network_policy(name, namespace)
        except self._ApiException as e:
            if e.status != 404:
                raise

    def expired(self, namespaces: list[str]) -> list[tuple[str, str, str]]:
        """Politiques gérées par l'orchestrateur, encore en mode audit, dont le TTL est dépassé."""
        now, out = time.time(), []
        for ns in namespaces:
            kas = self.custom.list_namespaced_custom_object(
                KA_GROUP, KA_VERSION, ns, KA_PLURAL, label_selector=MANAGED)["items"]
            for item in kas:
                if _is_expired(item["metadata"], now):
                    out.append(("KubeArmorPolicy", ns, item["metadata"]["name"]))
            for np in self.net.list_namespaced_network_policy(ns, label_selector=MANAGED).items:
                meta = {"labels": np.metadata.labels or {}, "annotations": np.metadata.annotations or {}}
                if _is_expired(meta, now):
                    out.append(("NetworkPolicy", ns, np.metadata.name))
        return out


def _is_expired(meta: dict, now: float) -> bool:
    if (meta.get("labels") or {}).get("mode") != "audit":
        return False  # une politique confirmée (block) reste en place
    exp = (meta.get("annotations") or {}).get("orchestrator/expires-at", "never")
    return exp != "never" and float(exp) < now
