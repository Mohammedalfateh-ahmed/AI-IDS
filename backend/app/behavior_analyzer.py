"""
Behavioral Anomaly Detection System for AI-IDS
===============================================
Learns normal behavior patterns for each IP and detects anomalies
that indicate potential threats, even if ML model doesn't classify as attack.

Author: Mohammed Alfateh
Project: AI-IDS Graduation Project
"""

import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict, deque
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import logging

logger = logging.getLogger(__name__)


class BehaviorAnalyzer:
    """
    Analyzes network behavior and detects anomalies using statistical methods.
    Learns baseline behavior for each IP and flags deviations.
    """
    
    def __init__(self, learning_period_minutes=60, anomaly_threshold=3.0):
        """
        Initialize Behavior Analyzer
        
        Args:
            learning_period_minutes: Time to learn baseline (default 60 min)
            anomaly_threshold: Sigma threshold for anomaly (default 3.0)
        """
        self.learning_period = timedelta(minutes=learning_period_minutes)
        self.anomaly_threshold = anomaly_threshold
        
        # IP behavior profiles
        self.ip_profiles = defaultdict(lambda: {
            'packet_sizes': deque(maxlen=1000),
            'packet_intervals': deque(maxlen=1000),
            'ports_used': defaultdict(int),
            'protocols_used': defaultdict(int),
            'packet_count': 0,
            'first_seen': None,
            'last_seen': None,
            'total_bytes': 0,
            'hourly_activity': defaultdict(int),  # Track activity by hour
            'behavior_learned': False
        })
        
        # Anomaly history
        self.anomaly_history = []
        
        # Load existing profiles if available
        self.profile_file = Path("data/behavior_profiles.json")
        self.load_profiles()
        
        logger.info("✅ Behavioral Anomaly Detection initialized")
    
    def update_profile(self, ip: str, packet_data: dict):
        """
        Update behavioral profile for an IP
        
        Args:
            packet_data: {
                'size': int,
                'port': int,
                'protocol': str,
                'timestamp': datetime
            }
        """
        profile = self.ip_profiles[ip]
        current_time = packet_data.get('timestamp', datetime.now())
        
        # First time seeing this IP
        if profile['first_seen'] is None:
            profile['first_seen'] = current_time
        
        # Update packet size history
        packet_size = packet_data.get('size', 0)
        profile['packet_sizes'].append(packet_size)
        profile['total_bytes'] += packet_size
        
        # Update packet intervals (time between packets)
        if profile['last_seen'] is not None:
            interval = (current_time - profile['last_seen']).total_seconds()
            if interval < 60:  # Only track intervals < 1 min
                profile['packet_intervals'].append(interval)
        
        profile['last_seen'] = current_time
        profile['packet_count'] += 1
        
        # Update port usage
        port = packet_data.get('port', 0)
        if port:
            profile['ports_used'][port] += 1
        
        # Update protocol usage
        protocol = packet_data.get('protocol', 'unknown')
        profile['protocols_used'][protocol] += 1
        
        # Update hourly activity pattern
        hour = current_time.hour
        profile['hourly_activity'][hour] += 1
        
        # Check if learning period is complete
        if not profile['behavior_learned']:
            time_observed = current_time - profile['first_seen']
            if time_observed >= self.learning_period and profile['packet_count'] >= 100:
                profile['behavior_learned'] = True
                logger.info(f"✅ Baseline learned for {ip} - {profile['packet_count']} packets over {time_observed}")
    
    def calculate_anomaly_score(self, ip: str, current_packet: dict) -> Tuple[float, Dict]:
        """
        Calculate anomaly score for current packet based on learned baseline
        
        Returns:
            (anomaly_score, anomaly_details)
        """
        profile = self.ip_profiles[ip]
        
        # If baseline not learned yet, return low score
        if not profile['behavior_learned']:
            return 0.0, {'reason': 'Learning baseline', 'learning_progress': f"{profile['packet_count']}/100 packets"}
        
        anomalies = {}
        total_score = 0.0
        
        # 1. Packet Size Anomaly
        current_size = current_packet.get('size', 0)
        if len(profile['packet_sizes']) > 10:
            mean_size = np.mean(profile['packet_sizes'])
            std_size = np.std(profile['packet_sizes'])
            
            if std_size > 0:
                size_deviation = abs(current_size - mean_size) / std_size
                if size_deviation > self.anomaly_threshold:
                    anomalies['packet_size'] = {
                        'deviation': round(size_deviation, 2),
                        'current': current_size,
                        'normal': round(mean_size, 2),
                        'severity': 'HIGH' if size_deviation > 5 else 'MEDIUM'
                    }
                    total_score += min(size_deviation * 10, 50)  # Cap at 50 points
        
        # 2. Packet Rate Anomaly (intervals between packets)
        if len(profile['packet_intervals']) > 10:
            mean_interval = np.mean(profile['packet_intervals'])
            std_interval = np.std(profile['packet_intervals'])
            
            current_time = current_packet.get('timestamp', datetime.now())
            if profile['last_seen']:
                current_interval = (current_time - profile['last_seen']).total_seconds()
                
                if std_interval > 0 and current_interval < 60:
                    rate_deviation = abs(current_interval - mean_interval) / std_interval
                    if rate_deviation > self.anomaly_threshold:
                        anomalies['packet_rate'] = {
                            'deviation': round(rate_deviation, 2),
                            'current_interval': round(current_interval, 3),
                            'normal_interval': round(mean_interval, 3),
                            'severity': 'HIGH' if rate_deviation > 5 else 'MEDIUM'
                        }
                        total_score += min(rate_deviation * 8, 40)  # Cap at 40 points
        
        # 3. Unusual Port Usage
        current_port = current_packet.get('port', 0)
        if current_port:
            total_port_usage = sum(profile['ports_used'].values())
            common_ports = {port: count for port, count in profile['ports_used'].items() 
                          if count / total_port_usage > 0.05}  # Ports used > 5% of time
            
            if current_port not in common_ports and total_port_usage > 50:
                anomalies['unusual_port'] = {
                    'port': current_port,
                    'typical_ports': list(common_ports.keys())[:5],
                    'severity': 'HIGH' if current_port in [4444, 31337, 12345] else 'MEDIUM'
                }
                total_score += 30
        
        # 4. Protocol Deviation
        current_protocol = current_packet.get('protocol', 'unknown')
        total_protocols = sum(profile['protocols_used'].values())
        if total_protocols > 20:
            common_protocols = {proto: count for proto, count in profile['protocols_used'].items()
                              if count / total_protocols > 0.1}  # Protocols used > 10%
            
            if current_protocol not in common_protocols:
                anomalies['unusual_protocol'] = {
                    'protocol': current_protocol,
                    'typical_protocols': list(common_protocols.keys()),
                    'severity': 'MEDIUM'
                }
                total_score += 20
        
        # 5. Time-based Anomaly (unusual activity hours)
        current_hour = current_packet.get('timestamp', datetime.now()).hour
        total_hourly = sum(profile['hourly_activity'].values())
        
        if total_hourly > 50:
            typical_hours = {hour: count for hour, count in profile['hourly_activity'].items()
                           if count / total_hourly > 0.05}  # Active > 5% of time
            
            if current_hour not in typical_hours:
                anomalies['unusual_time'] = {
                    'current_hour': current_hour,
                    'typical_hours': list(typical_hours.keys()),
                    'severity': 'LOW' if 0 <= current_hour <= 6 else 'VERY_LOW'
                }
                total_score += 15
        
        return min(total_score, 100), anomalies  # Cap total score at 100
    
    def detect_anomaly(self, ip: str, packet_data: dict) -> Dict:
        """
        Main detection function - updates profile and checks for anomalies
        
        Returns:
            {
                'is_anomalous': bool,
                'anomaly_score': float,
                'anomalies_detected': dict,
                'risk_level': str,
                'recommendation': str
            }
        """
        # Update profile with new packet
        self.update_profile(ip, packet_data)
        
        # Calculate anomaly score
        anomaly_score, anomalies = self.calculate_anomaly_score(ip, packet_data)
        
        # Determine risk level
        if anomaly_score >= 80:
            risk_level = "CRITICAL"
            recommendation = "BLOCK IMMEDIATELY - Highly anomalous behavior"
        elif anomaly_score >= 60:
            risk_level = "HIGH"
            recommendation = "Monitor closely - Suspicious activity"
        elif anomaly_score >= 40:
            risk_level = "MEDIUM"
            recommendation = "Investigate - Unusual pattern detected"
        elif anomaly_score >= 20:
            risk_level = "LOW"
            recommendation = "Normal with minor deviations"
        else:
            risk_level = "NORMAL"
            recommendation = "Behavior within expected parameters"
        
        result = {
            'is_anomalous': anomaly_score >= 40,  # Threshold for flagging
            'anomaly_score': round(anomaly_score, 2),
            'anomalies_detected': anomalies,
            'risk_level': risk_level,
            'recommendation': recommendation,
            'baseline_learned': self.ip_profiles[ip]['behavior_learned'],
            'packets_analyzed': self.ip_profiles[ip]['packet_count']
        }
        
        # Log if anomalous
        if result['is_anomalous']:
            self.anomaly_history.append({
                'timestamp': datetime.now(),
                'ip': ip,
                'score': anomaly_score,
                'anomalies': anomalies,
                'risk_level': risk_level
            })
            
            logger.warning(f"🚨 ANOMALY DETECTED | IP: {ip} | Score: {anomaly_score} | Risk: {risk_level}")
        
        return result
    
    def get_ip_profile_summary(self, ip: str) -> Dict:
        """Get summary of IP's behavioral profile"""
        if ip not in self.ip_profiles:
            return {'status': 'unknown', 'message': 'IP not tracked'}
        
        profile = self.ip_profiles[ip]
        
        return {
            'ip_address': ip,
            'baseline_learned': profile['behavior_learned'],
            'packets_observed': profile['packet_count'],
            'total_bytes': profile['total_bytes'],
            'first_seen': profile['first_seen'].isoformat() if profile['first_seen'] else None,
            'last_seen': profile['last_seen'].isoformat() if profile['last_seen'] else None,
            'avg_packet_size': round(np.mean(profile['packet_sizes']), 2) if profile['packet_sizes'] else 0,
            'typical_ports': list(dict(sorted(profile['ports_used'].items(), key=lambda x: x[1], reverse=True)[:5]).keys()),
            'typical_protocols': list(dict(sorted(profile['protocols_used'].items(), key=lambda x: x[1], reverse=True)[:3]).keys()),
            'most_active_hours': list(dict(sorted(profile['hourly_activity'].items(), key=lambda x: x[1], reverse=True)[:3]).keys())
        }
    
    def get_all_anomalies(self, limit=50) -> List[Dict]:
        """Get recent anomalies"""
        return sorted(self.anomaly_history, key=lambda x: x['timestamp'], reverse=True)[:limit]
    
    def get_statistics(self) -> Dict:
        """Get system-wide statistics"""
        total_ips = len(self.ip_profiles)
        learned_ips = sum(1 for p in self.ip_profiles.values() if p['behavior_learned'])
        total_anomalies = len(self.anomaly_history)
        
        # Recent anomalies (last hour)
        one_hour_ago = datetime.now() - timedelta(hours=1)
        recent_anomalies = sum(1 for a in self.anomaly_history if a['timestamp'] > one_hour_ago)
        
        # Risk distribution
        risk_distribution = defaultdict(int)
        for a in self.anomaly_history[-100:]:  # Last 100 anomalies
            risk_distribution[a['risk_level']] += 1
        
        return {
            'total_ips_tracked': total_ips,
            'baselines_learned': learned_ips,
            'total_anomalies_detected': total_anomalies,
            'anomalies_last_hour': recent_anomalies,
            'risk_distribution': dict(risk_distribution),
            'learning_progress': f"{learned_ips}/{total_ips} IPs"
        }
    
    def save_profiles(self):
        """Save profiles to disk"""
        try:
            self.profile_file.parent.mkdir(exist_ok=True)
            
            # Convert to JSON-serializable format
            serializable = {}
            for ip, profile in self.ip_profiles.items():
                serializable[ip] = {
                    'packet_sizes': list(profile['packet_sizes']),
                    'packet_intervals': list(profile['packet_intervals']),
                    'ports_used': dict(profile['ports_used']),
                    'protocols_used': dict(profile['protocols_used']),
                    'packet_count': profile['packet_count'],
                    'first_seen': profile['first_seen'].isoformat() if profile['first_seen'] else None,
                    'last_seen': profile['last_seen'].isoformat() if profile['last_seen'] else None,
                    'total_bytes': profile['total_bytes'],
                    'hourly_activity': dict(profile['hourly_activity']),
                    'behavior_learned': profile['behavior_learned']
                }
            
            with open(self.profile_file, 'w') as f:
                json.dump(serializable, f, indent=2)
            
            logger.info(f"💾 Saved {len(serializable)} behavioral profiles")
        except Exception as e:
            logger.error(f"❌ Failed to save profiles: {e}")
    
    def load_profiles(self):
        """Load profiles from disk"""
        try:
            if self.profile_file.exists():
                with open(self.profile_file, 'r') as f:
                    data = json.load(f)
                
                for ip, profile_data in data.items():
                    profile = self.ip_profiles[ip]
                    profile['packet_sizes'] = deque(profile_data['packet_sizes'], maxlen=1000)
                    profile['packet_intervals'] = deque(profile_data['packet_intervals'], maxlen=1000)
                    profile['ports_used'] = defaultdict(int, profile_data['ports_used'])
                    profile['protocols_used'] = defaultdict(int, profile_data['protocols_used'])
                    profile['packet_count'] = profile_data['packet_count']
                    profile['first_seen'] = datetime.fromisoformat(profile_data['first_seen']) if profile_data['first_seen'] else None
                    profile['last_seen'] = datetime.fromisoformat(profile_data['last_seen']) if profile_data['last_seen'] else None
                    profile['total_bytes'] = profile_data['total_bytes']
                    profile['hourly_activity'] = defaultdict(int, profile_data['hourly_activity'])
                    profile['behavior_learned'] = profile_data['behavior_learned']
                
                logger.info(f"✅ Loaded {len(data)} behavioral profiles from disk")
        except Exception as e:
            logger.error(f"⚠️ Could not load profiles: {e}")


# Global instance
behavior_analyzer = BehaviorAnalyzer(
    learning_period_minutes=60,  # 1 hour to learn baseline
    anomaly_threshold=3.0        # 3-sigma rule
)


def analyze_packet_behavior(ip: str, packet_data: dict) -> Dict:
    """
    Convenience function to analyze packet behavior
    
    Usage:
        result = analyze_packet_behavior('192.168.1.100', {
            'size': 1500,
            'port': 80,
            'protocol': 'TCP',
            'timestamp': datetime.now()
        })
    """
    return behavior_analyzer.detect_anomaly(ip, packet_data)