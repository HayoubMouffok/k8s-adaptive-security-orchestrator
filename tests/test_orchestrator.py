import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from orchestrator.app import create_app
from orchestrator.classifier import classify
from orchestrator.config import Config
from orchestrator.policy import build_policy

NOW = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "123Z"


def alert(rule, priority="Critical", **fields):
    base = {"k8s.ns.name": "demo", "k8s.pod.name": "web-7d9f-abcde"}
    base.update(fields)
    return {"rule": rule, "priority": priority, "time": NOW, "output_fields": base, "tags": []}


class FakeKube:
    def __init__(self):
        self.applied, self.deleted = [], []

    def pod_labels(self, ns, pod):
        return {"app": "web", "pod-template-hash": "7d9f"}

    def apply(self, manifest):
        self.applied.append(manifest)
        return "created"

    def delete(self, kind, ns, name):
        self.deleted.append((kind, ns, name))

    def expired(self, namespaces):
        return []


# --- classification ---------------------------------------------------------

def test_shell_is_t1059():
    ev = classify(alert("Terminal shell in container", **{"proc.name": "bash", "proc.exepath": "/bin/bash"}))
    assert ev.threat_type == "shell_execution" and ev.mitre_id == "T1059"


def test_shadow_read_is_credential_dumping():
    ev = classify(alert("Read sensitive file untrusted", **{"fd.name": "/etc/shadow", "proc.name": "cat"}))
    assert ev.threat_type == "sensitive_file_access" and ev.file_path == "/etc/shadow"


def test_falco_mitre_tag_takes_precedence():
    a = alert("Terminal shell in container", **{"proc.name": "sh"})
    a["tags"] = ["mitre_execution", "T1059.004"]
    assert classify(a).mitre_id == "T1059.004"


def test_network_extracts_remote_ip():
    ev = classify(alert("Outbound connection to C2 server", **{"fd.name": "10.0.0.5:4444->203.0.113.7:443"}))
    assert ev.threat_type == "network_activity" and ev.remote_ip == "203.0.113.7"


def test_nanosecond_timestamp_is_parsed():
    assert classify(alert("x")).alert_time.year == datetime.now(timezone.utc).year


# --- génération de politiques -------------------------------------------------

def test_policy_targets_pod_labels_not_namespace():
    ev = classify(alert("Terminal shell in container", **{"proc.name": "bash", "proc.exepath": "/bin/bash"}))
    p = build_policy(ev, {"app": "web", "pod-template-hash": "x"}, block=True, ttl=0)
    assert p["kind"] == "KubeArmorPolicy"
    assert p["spec"]["selector"]["matchLabels"] == {"app": "web"}
    assert p["spec"]["action"] == "Block"
    assert {"path": "/bin/bash"} in p["spec"]["process"]["matchPaths"]


def test_audit_mode_has_expiry():
    ev = classify(alert("Read sensitive file untrusted", "Warning", **{"fd.name": "/etc/shadow"}))
    p = build_policy(ev, {"app": "web"}, block=False, ttl=600)
    assert p["spec"]["action"] == "Audit"
    assert p["metadata"]["annotations"]["orchestrator/expires-at"] != "never"


def test_network_block_is_networkpolicy():
    ev = classify(alert("Outbound connection to C2 server", **{"fd.name": "1.1.1.1:1->203.0.113.7:443"}))
    p = build_policy(ev, {"app": "web"}, block=True, ttl=0)
    assert p["kind"] == "NetworkPolicy"
    assert p["spec"]["egress"][0]["to"][0]["ipBlock"]["except"] == ["203.0.113.7/32"]


def test_pod_without_labels_is_refused():
    ev = classify(alert("Terminal shell in container", **{"proc.name": "bash"}))
    with pytest.raises(ValueError):
        build_policy(ev, {"pod-template-hash": "x"}, block=True, ttl=0)


# --- API --------------------------------------------------------------------

def make(cfg=None):
    kube = FakeKube()
    app = create_app(kube=kube, cfg=cfg or Config(watched_namespaces=["demo"]), start_reaper=False)
    return app.test_client(), kube


def test_critical_alert_is_blocked_immediately():
    c, kube = make()
    r = c.post("/falco", json=alert("Terminal shell in container", **{"proc.name": "bash"})).get_json()
    assert r["action"] == "block" and [m["kind"] for m in kube.applied] == ["KubeArmorPolicy", "NamespacedValidatingPolicy"]
    assert r["latency_s"] < 5


def test_warning_alert_waits_for_human_then_approve():
    c, kube = make()
    r = c.post("/falco", json=alert("Read sensitive file untrusted", "Warning",
                                    **{"fd.name": "/etc/shadow"})).get_json()
    assert r["action"] == "audit"
    assert kube.applied[-1]["spec"]["action"] == "Audit"
    a = c.post(f"/approve/demo/{r['policy']}").get_json()
    assert a["mode"] == "block" and kube.applied[-1]["spec"]["action"] == "Block"
    # une nouvelle alerte identique ne doit pas repasser la politique validée en audit
    r2 = c.post("/falco", json=alert("Read sensitive file untrusted", "Warning",
                                     **{"fd.name": "/etc/shadow"})).get_json()
    assert r2["action"] == "block" and kube.applied[-1]["spec"]["action"] == "Block"


def test_reject_counts_false_positive_and_deletes():
    c, kube = make()
    r = c.post("/falco", json=alert("Read sensitive file untrusted", "Warning",
                                    **{"fd.name": "/etc/shadow"})).get_json()
    assert c.post(f"/reject/demo/{r['policy']}").get_json()["false_positive"] is True
    assert kube.deleted and b"orchestrator_false_positives_total" in c.get("/metrics").data


def test_unwatched_namespace_is_ignored():
    c, kube = make()
    a = alert("Terminal shell in container", **{"proc.name": "bash", "k8s.ns.name": "kube-system"})
    assert c.post("/falco", json=a).get_json()["action"] == "ignored" and not kube.applied


@pytest.mark.parametrize("rule,fields,expected,kind", [
    ("Read service account token in container",
     {"fd.name": "/run/secrets/kubernetes.io/serviceaccount/..2026/token", "proc.name": "cat"},
     "token_theft", "file"),
    ("Binary executed from temporary directory", {"proc.exepath": "/tmp/scan", "proc.name": "scan"},
     "untrusted_binary", "process"),
    ("Write below binary dir in container", {"fd.name": "/usr/bin/backdoor", "proc.name": "touch"},
     "binary_tampering", "file"),
])
def test_new_threat_types_build_directory_policies(rule, fields, expected, kind):
    ev = classify(alert(rule, "Warning", **fields))
    assert ev.threat_type == expected
    pol = build_policy(ev, {"app": "web"}, block=True, ttl=0)
    assert pol["spec"]["action"] == "Block" and pol["spec"][kind]["matchDirectories"]


def test_blocked_shell_also_denies_kubectl_exec_with_kyverno():
    c, kube = make()
    r = c.post("/falco", json=alert("Terminal shell in container", "Notice",
                                    **{"proc.name": "sh"})).get_json()
    assert r["action"] == "audit" and not any(m["kind"] == "NamespacedValidatingPolicy" for m in kube.applied)
    c.post(f"/approve/demo/{r['policy']}")
    guard = [m for m in kube.applied if m["kind"] == "NamespacedValidatingPolicy"][-1]
    spec = guard["spec"]
    assert spec["matchConstraints"]["resourceRules"][0]["resources"] == ["pods/exec"]
    assert spec["matchConstraints"]["resourceRules"][0]["operations"] == ["CONNECT"]
    assert spec["validations"][0]["expression"] == (
        """!(variables.pod.metadata.?labels["app"].orValue('') == "web")""")
