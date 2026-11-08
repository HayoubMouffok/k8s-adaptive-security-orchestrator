"""Extraits de l'orchestrateur de sécurité (mémoire de Master CNAM, 2025)."""
from datetime import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)


class SecurityOrchestrator:
    def __init__(self):
        self.threat_classifier = ThreatClassifier()
        self.policy_generator = PolicyGenerator()
        self.kubernetes_client = KubernetesAPIClient()
        self.stats_collector = StatsCollector()

    def process_threat_event(self, event):
        # Classification automatique du type de menace
        threat_type = self.threat_classifier.classify(event)
        # Génération de politique contextuelle
        policy = self.policy_generator.create_policy(threat_type, event.context)
        # Application via l'API Kubernetes
        result = self.kubernetes_client.apply_policy(policy)
        # Collecte de métriques
        self.stats_collector.record_processing(event, policy, result)
        return result

    def analyze_threat(self, alert):
        rule = alert.get('rule', '').lower()
        output_fields = alert.get('output_fields', {})
        proc_name = output_fields.get('proc.name', '').lower()
        if 'shell' in rule or proc_name in ['bash', 'sh']:
            return 'shell_execution'
        elif 'file' in rule or '/etc/' in str(output_fields.get('fd.name', '')):
            return 'file_access'
        elif 'network' in rule:
            return 'network_activity'
        return 'file_access'


class ThreatSimulator:
    def generate_file_access_event(self):
        return {'type': 'file_access', 'container': 'test-app', 'file_path': '/etc/shadow',
                'timestamp': datetime.now(), 'severity': 'high'}

    def generate_shell_execution_event(self):
        return {'type': 'shell_execution', 'container': 'test-app', 'command': '/bin/bash',
                'timestamp': datetime.now(), 'severity': 'medium'}


@app.route('/simulate', methods=['POST'])
def simulate_attack():
    attack_type = request.json.get('type', 'file_access')
    alert = simulated_alerts[attack_type]
    result = orchestrator.process_security_alert(alert)
    return jsonify({'attack_simulated': attack_type, 'policy_generated': result,
                    'timestamp': datetime.now().isoformat()}), 200


@app.route('/stats', methods=['GET'])
def get_statistics():
    return jsonify(orchestrator.stats_collector.get_summary())
