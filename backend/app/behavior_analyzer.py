import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict, deque
import json
from pathlib import Path
from typing import Dict, List, Tuple
import logging

logger = logging.getLogger(__name__)


def sanitize(obj):
    if isinstance(obj, dict):
        return {sanitize(k): sanitize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sanitize(i) for i in obj]
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.floating):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    return obj


class BehaviorAnalyzer:

    def __init__(self, learning_period_minutes=1, anomaly_threshold=2.5):
        self.learning_period   = timedelta(minutes=learning_period_minutes)
        self.anomaly_threshold = anomaly_threshold
        self.ip_profiles = defaultdict(lambda: {
            'packet_sizes':     deque(maxlen=1000),
            'packet_intervals': deque(maxlen=1000),
            'ports_used':       defaultdict(int),
            'protocols_used':   defaultdict(int),
            'packet_count':     0,
            'first_seen':       None,
            'last_seen':        None,
            'total_bytes':      0,
            'hourly_activity':  defaultdict(int),
            'behavior_learned': False
        })
        self.anomaly_history = []
        self.profile_file    = Path("data/behavior_profiles.json")
        self._seed_baseline_ips()
        self.load_profiles()
        logger.info("BehaviorAnalyzer initialized — full attack range seeded")

    def _seed_baseline_ips(self):
        now = datetime.now()

        seed_configs = [
            ("192.168.1.100", (800, 1200),  [80, 443, 80, 443, 22],      60),
            ("192.168.1.101", (400, 800),   [80, 443, 22, 53, 8080],     60),
            ("192.168.1.102", (500, 1000),  [21, 23, 110, 21, 23],       60),
            ("192.168.1.103", (900, 1400),  [80, 443, 22, 80, 443],      60),
            ("192.168.1.110", (600, 1000),  [80, 443, 22],               50),
            ("192.168.1.120", (700, 1100),  [80, 443, 53],               50),
            ("192.168.1.130", (650, 950),   [80, 443, 22, 53],           50),
            ("192.168.1.140", (750, 1050),  [80, 443],                   50),
            ("192.168.1.150", (800, 1200),  [80, 443, 22],               50),
        ]

        seeded_ips = {cfg[0] for cfg in seed_configs}
        for last_octet in range(100, 251):
            ip = f"192.168.1.{last_octet}"
            if ip not in seeded_ips:
                seed_configs.append((ip, (700, 1300), [80, 443, 22, 53], 50))

        for ip, size_range, ports, count in seed_configs:
            p = self.ip_profiles[ip]
            p['first_seen'] = now - timedelta(minutes=15)

            for i in range(count):
                size = int(np.random.randint(*size_range))
                p['packet_sizes'].append(size)
                p['total_bytes'] += size

                if i > 0:
                    p['packet_intervals'].append(float(np.random.uniform(0.1, 1.0)))

                p['ports_used'][int(ports[i % len(ports)])] += 1
                p['protocols_used']['TCP'] += 1
                p['hourly_activity'][9 + (i % 8)] += 1

            p['packet_count']     = count
            p['last_seen']        = now - timedelta(seconds=10)
            p['behavior_learned'] = True

        logger.info("Seeded baselines for 192.168.1.100 through 192.168.1.250 (151 IPs)")

    def _check_new_ip_fast_track(self, ip: str, packet_data: dict) -> Tuple[float, Dict]:
        anomalies = {}
        score     = 0.0

        size = int(packet_data.get('size', 0))
        port = int(packet_data.get('port', 0))

        if size < 200:
            anomalies['packet_size'] = {
                'deviation': 5.0,
                'current':   size,
                'normal':    1000,
                'severity':  'HIGH'
            }
            score += 35

        if size > 4000:
            anomalies['packet_size'] = {
                'deviation': 6.0,
                'current':   size,
                'normal':    1000,
                'severity':  'HIGH'
            }
            score += 45

        if port in [4444, 31337, 12345, 1337, 9999, 6666]:
            anomalies['unusual_port'] = {
                'port':          port,
                'typical_ports': [80, 443, 22, 53],
                'severity':      'HIGH'
            }
            score += 40

        elif port > 10000 and port not in [8080, 8443]:
            anomalies['unusual_port'] = {
                'port':          port,
                'typical_ports': [80, 443, 22, 53],
                'severity':      'MEDIUM'
            }
            score += 20

        return min(score, 100), anomalies

    def update_profile(self, ip: str, packet_data: dict):
        p = self.ip_profiles[ip]
        t = packet_data.get('timestamp', datetime.now())

        if p['first_seen'] is None:
            p['first_seen'] = t

        size = int(packet_data.get('size', 0))
        p['packet_sizes'].append(size)
        p['total_bytes'] += size

        if p['last_seen']:
            iv = (t - p['last_seen']).total_seconds()
            if iv < 60:
                p['packet_intervals'].append(float(iv))

        p['last_seen']     = t
        p['packet_count'] += 1

        port = packet_data.get('port', 0)
        if port:
            p['ports_used'][int(port)] += 1

        p['protocols_used'][packet_data.get('protocol', 'unknown')] += 1
        p['hourly_activity'][t.hour] += 1

        if not p['behavior_learned']:
            if (t - p['first_seen']) >= self.learning_period and p['packet_count'] >= 10:
                p['behavior_learned'] = True
                logger.info(f"Baseline learned for {ip} after {p['packet_count']} packets")

    def calculate_anomaly_score(self, ip: str, pkt: dict) -> Tuple[float, Dict]:
        p = self.ip_profiles[ip]

        if not p['behavior_learned']:
            return self._check_new_ip_fast_track(ip, pkt)

        anomalies = {}
        score     = 0.0

        if len(p['packet_sizes']) > 5:
            mu    = float(np.mean(p['packet_sizes']))
            sigma = float(np.std(p['packet_sizes']))

            if sigma > 0:
                z = abs(int(pkt.get('size', 0)) - mu) / sigma
                if z > self.anomaly_threshold:
                    anomalies['packet_size'] = {
                        'deviation': round(float(z), 2),
                        'current':   int(pkt.get('size', 0)),
                        'normal':    round(mu, 2),
                        'severity':  'HIGH' if z > 5 else 'MEDIUM'
                    }
                    score += min(z * 10, 50)

        if len(p['packet_intervals']) > 5:
            mu    = float(np.mean(p['packet_intervals']))
            sigma = float(np.std(p['packet_intervals']))
            t     = pkt.get('timestamp', datetime.now())

            if p['last_seen'] and sigma > 0:
                iv = (t - p['last_seen']).total_seconds()
                if iv < 60:
                    z = abs(iv - mu) / sigma
                    if z > self.anomaly_threshold:
                        anomalies['packet_rate'] = {
                            'deviation':        round(float(z), 2),
                            'current_interval': round(float(iv), 3),
                            'normal_interval':  round(float(mu), 3),
                            'severity':         'HIGH' if z > 5 else 'MEDIUM'
                        }
                        score += min(z * 8, 40)

        port  = int(pkt.get('port', 0))
        total = sum(p['ports_used'].values())
        if port and total > 5:
            common = {k: v for k, v in p['ports_used'].items() if v / total > 0.05}
            if port not in common:
                anomalies['unusual_port'] = {
                    'port':          port,
                    'typical_ports': [int(k) for k in list(common.keys())[:5]],
                    'severity':      'HIGH' if port in [4444, 31337, 12345] else 'MEDIUM'
                }
                score += 30

        proto = pkt.get('protocol', 'unknown')
        total = sum(p['protocols_used'].values())
        if total > 5:
            common = {k: v for k, v in p['protocols_used'].items() if v / total > 0.1}
            if proto not in common:
                anomalies['unusual_protocol'] = {
                    'protocol':          proto,
                    'typical_protocols': list(common.keys()),
                    'severity':          'MEDIUM'
                }
                score += 20

        hour  = pkt.get('timestamp', datetime.now()).hour
        total = sum(p['hourly_activity'].values())
        if total > 5:
            common = {h: c for h, c in p['hourly_activity'].items() if c / total > 0.05}
            if hour not in common:
                anomalies['unusual_time'] = {
                    'current_hour':  int(hour),
                    'typical_hours': [int(h) for h in list(common.keys())],
                    'severity':      'LOW'
                }
                score += 15

        return min(score, 100), anomalies

    def detect_anomaly(self, ip: str, packet_data: dict) -> Dict:
        self.update_profile(ip, packet_data)
        score, anomalies = self.calculate_anomaly_score(ip, packet_data)

        if score >= 80:
            risk = "CRITICAL"
            rec  = "BLOCK IMMEDIATELY - Highly anomalous behavior"
        elif score >= 60:
            risk = "HIGH"
            rec  = "Monitor closely - Suspicious activity"
        elif score >= 40:
            risk = "MEDIUM"
            rec  = "Investigate - Unusual pattern detected"
        elif score >= 20:
            risk = "LOW"
            rec  = "Normal with minor deviations"
        else:
            risk = "NORMAL"
            rec  = "Behavior within expected parameters"

        result = sanitize({
            'is_anomalous':       score >= 40,
            'anomaly_score':      round(score, 2),
            'anomalies_detected': anomalies,
            'risk_level':         risk,
            'recommendation':     rec,
            'baseline_learned':   self.ip_profiles[ip]['behavior_learned'],
            'packets_analyzed':   self.ip_profiles[ip]['packet_count']
        })

        if result['is_anomalous']:
            self.anomaly_history.append(sanitize({
                'timestamp':  datetime.now(),
                'ip':         ip,
                'score':      score,
                'anomalies':  anomalies,
                'risk_level': risk
            }))
            logger.warning(f"ANOMALY DETECTED | IP: {ip} | Score: {score} | Risk: {risk}")

        return result

    def get_ip_profile_summary(self, ip: str) -> Dict:
        if ip not in self.ip_profiles:
            return {'status': 'unknown', 'message': 'IP not tracked'}

        p = self.ip_profiles[ip]
        return sanitize({
            'ip_address':        ip,
            'baseline_learned':  p['behavior_learned'],
            'packets_observed':  p['packet_count'],
            'total_bytes':       p['total_bytes'],
            'first_seen':        p['first_seen'].isoformat() if p['first_seen'] else None,
            'last_seen':         p['last_seen'].isoformat()  if p['last_seen']  else None,
            'avg_packet_size':   round(float(np.mean(p['packet_sizes'])), 2) if p['packet_sizes'] else 0,
            'typical_ports':     list(dict(sorted(p['ports_used'].items(),      key=lambda x: x[1], reverse=True)[:5]).keys()),
            'typical_protocols': list(dict(sorted(p['protocols_used'].items(),  key=lambda x: x[1], reverse=True)[:3]).keys()),
            'most_active_hours': list(dict(sorted(p['hourly_activity'].items(), key=lambda x: x[1], reverse=True)[:3]).keys())
        })

    def get_all_anomalies(self, limit=50) -> List[Dict]:
        return sorted(self.anomaly_history, key=lambda x: x['timestamp'], reverse=True)[:limit]

    def get_statistics(self) -> Dict:
        total   = len(self.ip_profiles)
        learned = sum(1 for p in self.ip_profiles.values() if p['behavior_learned'])
        cutoff  = datetime.now() - timedelta(hours=1)
        recent  = sum(1 for a in self.anomaly_history if a['timestamp'] > cutoff)

        dist = defaultdict(int)
        for a in self.anomaly_history[-100:]:
            dist[a['risk_level']] += 1

        return sanitize({
            'total_ips_tracked':        total,
            'baselines_learned':        learned,
            'total_anomalies_detected': len(self.anomaly_history),
            'anomalies_last_hour':      recent,
            'risk_distribution':        dict(dist),
            'learning_progress':        f"{learned}/{total} IPs"
        })

    def save_profiles(self):
        try:
            self.profile_file.parent.mkdir(exist_ok=True)
            out = {}
            for ip, p in self.ip_profiles.items():
                out[ip] = {
                    'packet_sizes':     [int(x) for x in p['packet_sizes']],
                    'packet_intervals': [float(x) for x in p['packet_intervals']],
                    'ports_used':       {int(k): int(v) for k, v in p['ports_used'].items()},
                    'protocols_used':   dict(p['protocols_used']),
                    'packet_count':     int(p['packet_count']),
                    'first_seen':       p['first_seen'].isoformat() if p['first_seen'] else None,
                    'last_seen':        p['last_seen'].isoformat()  if p['last_seen']  else None,
                    'total_bytes':      int(p['total_bytes']),
                    'hourly_activity':  {int(k): int(v) for k, v in p['hourly_activity'].items()},
                    'behavior_learned': bool(p['behavior_learned'])
                }
            with open(self.profile_file, 'w') as f:
                json.dump(out, f, indent=2)
            logger.info(f"Saved {len(out)} behavioral profiles")
        except Exception as e:
            logger.error(f"Failed to save profiles: {e}")

    def load_profiles(self):
        try:
            if self.profile_file.exists():
                with open(self.profile_file, 'r') as f:
                    data = json.load(f)

                for ip, d in data.items():
                    if ip in self.ip_profiles and self.ip_profiles[ip]['behavior_learned']:
                        continue

                    p = self.ip_profiles[ip]
                    p['packet_sizes']     = deque([int(x) for x in d['packet_sizes']],      maxlen=1000)
                    p['packet_intervals'] = deque([float(x) for x in d['packet_intervals']], maxlen=1000)
                    p['ports_used']       = defaultdict(int, {int(k): int(v) for k, v in d['ports_used'].items()})
                    p['protocols_used']   = defaultdict(int, d['protocols_used'])
                    p['packet_count']     = int(d['packet_count'])
                    p['first_seen']       = datetime.fromisoformat(d['first_seen']) if d['first_seen'] else None
                    p['last_seen']        = datetime.fromisoformat(d['last_seen'])  if d['last_seen']  else None
                    p['total_bytes']      = int(d['total_bytes'])
                    p['hourly_activity']  = defaultdict(int, {int(k): int(v) for k, v in d['hourly_activity'].items()})
                    p['behavior_learned'] = bool(d['behavior_learned'])

                logger.info(f"Loaded {len(data)} behavioral profiles from disk")
        except Exception as e:
            logger.error(f"Could not load profiles: {e}")


behavior_analyzer = BehaviorAnalyzer(
    learning_period_minutes=1,
    anomaly_threshold=2.5
)


def analyze_packet_behavior(ip: str, packet_data: dict) -> Dict:
    return behavior_analyzer.detect_anomaly(ip, packet_data)