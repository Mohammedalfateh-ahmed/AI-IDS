import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict

class IntelligenceEngine:
    def __init__(self):
        self.attack_history = []
        self.ip_profiles = defaultdict(lambda: {
            'total_packets': 0,
            'attack_count': 0,
            'first_seen': None,
            'last_seen': None,
            'attack_types': [],
            'risk_score': 0
        })
        self.baseline_confidence = 0.72
        
    def calculate_anomaly_score(self, features):
        feature_mean = np.mean(features)
        feature_std = np.std(features)
        
        anomaly_score = 0.0
        
        if feature_std > 0:
            z_scores = np.abs((features - feature_mean) / feature_std)
            anomaly_score = np.mean(z_scores > 2.5)
        
        unusual_ports = 0
        if features[0][3] > 49152 or features[0][4] > 49152:
            unusual_ports += 0.3
        
        if features[0][0] > 1500:
            unusual_ports += 0.2
        
        anomaly_score = min(1.0, anomaly_score + unusual_ports)
        
        return float(anomaly_score)
    
    def calculate_risk_score(self, source_ip, attack_type, confidence, anomaly_score):
        profile = self.ip_profiles[source_ip]
        
        profile['total_packets'] += 1
        if attack_type != 'normal':
            profile['attack_count'] += 1
            if attack_type not in profile['attack_types']:
                profile['attack_types'].append(attack_type)
        
        if profile['first_seen'] is None:
            profile['first_seen'] = datetime.now()
        profile['last_seen'] = datetime.now()
        
        attack_rate = profile['attack_count'] / max(profile['total_packets'], 1)
        
        diversity_score = len(profile['attack_types']) * 0.15
        
        frequency_score = min(1.0, profile['attack_count'] / 10) * 0.3
        
        confidence_score = confidence * 0.3
        
        anomaly_weight = anomaly_score * 0.25
        
        risk_score = min(100, (attack_rate * 40 + diversity_score * 100 + 
                               frequency_score * 100 + confidence_score * 100 + 
                               anomaly_weight * 100))
        
        profile['risk_score'] = risk_score
        
        return risk_score
    
    def get_threat_level(self, risk_score):
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        elif risk_score >= 20:
            return "LOW"
        else:
            return "MINIMAL"
    
    def should_escalate(self, source_ip, attack_type):
        profile = self.ip_profiles[source_ip]
        
        if profile['attack_count'] >= 5:
            return True, "Multiple attacks detected from this IP"
        
        if len(profile['attack_types']) >= 3:
            return True, "Diverse attack types indicate sophisticated attacker"
        
        time_window = timedelta(minutes=5)
        if profile['first_seen'] and profile['last_seen']:
            if (profile['last_seen'] - profile['first_seen']) < time_window:
                if profile['attack_count'] >= 3:
                    return True, "Rapid attack sequence detected"
        
        critical_attacks = ['buffer_overflow', 'rootkit', 'back']
        if attack_type in critical_attacks:
            return True, f"Critical attack type: {attack_type}"
        
        return False, None
    
    def predict_next_attack(self, recent_attacks):
        if len(recent_attacks) < 3:
            return None
        
        attack_sequence = [a['attack_type'] for a in recent_attacks[-10:]]
        
        attack_counts = defaultdict(int)
        for attack in attack_sequence:
            attack_counts[attack] += 1
        
        if attack_counts:
            most_common = max(attack_counts.items(), key=lambda x: x[1])
            return {
                'predicted_attack': most_common[0],
                'confidence': min(0.95, most_common[1] / len(attack_sequence)),
                'reason': f"Pattern analysis: {most_common[0]} appeared {most_common[1]} times in last 10 events"
            }
        
        return None
    
    def get_ip_reputation(self, source_ip):
        profile = self.ip_profiles[source_ip]
        
        if profile['total_packets'] == 0:
            return "UNKNOWN", 50
        
        attack_percentage = (profile['attack_count'] / profile['total_packets']) * 100
        
        if attack_percentage >= 80:
            return "MALICIOUS", profile['risk_score']
        elif attack_percentage >= 50:
            return "SUSPICIOUS", profile['risk_score']
        elif attack_percentage >= 20:
            return "QUESTIONABLE", profile['risk_score']
        else:
            return "TRUSTED", profile['risk_score']
    
    def get_network_health(self):
        total_ips = len(self.ip_profiles)
        if total_ips == 0:
            return {
                'status': 'UNKNOWN',
                'health_score': 100,
                'total_ips': 0,
                'malicious_ips': 0,
                'at_risk_ips': 0
            }
        
        malicious_count = sum(1 for p in self.ip_profiles.values() 
                             if p['risk_score'] >= 80)
        at_risk_count = sum(1 for p in self.ip_profiles.values() 
                           if 40 <= p['risk_score'] < 80)
        
        health_score = 100 - (malicious_count / total_ips * 50) - (at_risk_count / total_ips * 30)
        
        if health_score >= 80:
            status = "HEALTHY"
        elif health_score >= 60:
            status = "FAIR"
        elif health_score >= 40:
            status = "DEGRADED"
        else:
            status = "CRITICAL"
        
        return {
            'status': status,
            'health_score': round(health_score, 1),
            'total_ips': total_ips,
            'malicious_ips': malicious_count,
            'at_risk_ips': at_risk_count
        }

intelligence_engine = IntelligenceEngine()