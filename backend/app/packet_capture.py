import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP
import numpy as np
import threading
import time
from datetime import datetime
import psutil
import netifaces
from collections import defaultdict
import pickle
import os

class PacketCaptureService:
    def __init__(self, model_path, preprocessor_path):
        self.is_capturing = False
        self.capture_thread = None
        self.packets_captured = 0
        self.attacks_detected = 0
        self.packet_buffer = []
        self.flow_stats = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'start_time': None,
            'last_time': None,
            'flags': set(),
            'ports': set()
        })
        
        with open(model_path, 'rb') as f:
            self.model = pickle.load(f)
        with open(preprocessor_path, 'rb') as f:
            self.preprocessor = pickle.load(f)
        
        self.recent_alerts = []
        self.max_alerts = 100

    def get_available_interfaces(self):
        interfaces = []
        for iface in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    interfaces.append({
                        'name': iface,
                        'ip': ip
                    })
            except:
                pass
        return interfaces

    def extract_features(self, packet):
        features = np.zeros(119)
        
        try:
            if IP in packet:
                ip_layer = packet[IP]
                
                features[0] = len(packet)
                features[1] = ip_layer.proto
                
                flow_key = f"{ip_layer.src}:{ip_layer.dst}"
                flow = self.flow_stats[flow_key]
                
                if flow['start_time'] is None:
                    flow['start_time'] = time.time()
                flow['last_time'] = time.time()
                flow['packets'] += 1
                flow['bytes'] += len(packet)
                
                duration = flow['last_time'] - flow['start_time']
                features[2] = duration if duration > 0 else 0
                
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    features[3] = tcp_layer.sport
                    features[4] = tcp_layer.dport
                    features[5] = tcp_layer.flags
                    features[6] = tcp_layer.window
                    features[7] = 1
                    flow['flags'].add(str(tcp_layer.flags))
                    flow['ports'].add(tcp_layer.dport)
                
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    features[3] = udp_layer.sport
                    features[4] = udp_layer.dport
                    features[8] = 1
                    flow['ports'].add(udp_layer.dport)
                
                elif ICMP in packet:
                    features[9] = 1
                
                features[10] = flow['packets']
                features[11] = flow['bytes']
                features[12] = len(flow['flags'])
                features[13] = len(flow['ports'])
                
                if duration > 0:
                    features[14] = flow['packets'] / duration
                    features[15] = flow['bytes'] / duration
                
                features[16] = 1 if features[4] == 80 else 0
                features[17] = 1 if features[4] == 443 else 0
                features[18] = 1 if features[4] == 22 else 0
                features[19] = 1 if features[4] == 21 else 0
                
                if features[2] > 0:
                    features[20] = features[0] / features[2]
                
        except Exception as e:
            pass
        
        return features

    def process_packet(self, packet):
        try:
            if IP in packet:
                features = self.extract_features(packet)
                features_scaled = self.preprocessor.transform([features])
                prediction = self.model.predict(features_scaled)[0]
                
                self.packets_captured += 1
                
                ip_layer = packet[IP]
                packet_info = {
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': ip_layer.src,
                    'dst_ip': ip_layer.dst,
                    'protocol': ip_layer.proto,
                    'length': len(packet),
                    'prediction': prediction
                }
                
                if prediction != 'normal':
                    self.attacks_detected += 1
                    alert = {
                        **packet_info,
                        'severity': self.get_severity(prediction),
                        'attack_type': prediction
                    }
                    self.recent_alerts.insert(0, alert)
                    if len(self.recent_alerts) > self.max_alerts:
                        self.recent_alerts = self.recent_alerts[:self.max_alerts]
                
                self.packet_buffer.append(packet_info)
                if len(self.packet_buffer) > 1000:
                    self.packet_buffer = self.packet_buffer[-1000:]
                
        except Exception as e:
            pass

    def get_severity(self, attack_type):
        high_severity = ['DoS', 'DDoS', 'Exploits', 'rootkit', 'backdoor']
        medium_severity = ['Probe', 'Fuzzers', 'Reconnaissance']
        
        for keyword in high_severity:
            if keyword.lower() in attack_type.lower():
                return 'high'
        for keyword in medium_severity:
            if keyword.lower() in attack_type.lower():
                return 'medium'
        return 'low'

    def start_capture(self, interface=None):
        if self.is_capturing:
            return False
        
        self.is_capturing = True
        self.packets_captured = 0
        self.attacks_detected = 0
        
        def capture_loop():
            try:
                scapy.sniff(
                    iface=interface,
                    prn=self.process_packet,
                    store=False,
                    stop_filter=lambda x: not self.is_capturing
                )
            except Exception as e:
                self.is_capturing = False
        
        self.capture_thread = threading.Thread(target=capture_loop, daemon=True)
        self.capture_thread.start()
        return True

    def stop_capture(self):
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        return True

    def get_stats(self):
        return {
            'is_capturing': self.is_capturing,
            'packets_captured': self.packets_captured,
            'attacks_detected': self.attacks_detected,
            'recent_packets': self.packet_buffer[-20:],
            'recent_alerts': self.recent_alerts[:10]
        }

    def clear_stats(self):
        self.packets_captured = 0
        self.attacks_detected = 0
        self.packet_buffer = []
        self.recent_alerts = []
        self.flow_stats.clear()

capture_service = None

def get_capture_service():
    global capture_service
    if capture_service is None:
        model_path = 'data/models/xgboost_nslkdd_model.pkl'
        preprocessor_path = 'data/models/preprocessor_nslkdd.pkl'
        
        if not os.path.exists(model_path):
            for root, dirs, files in os.walk('data'):
                for file in files:
                    if 'xgboost' in file.lower() and file.endswith('.pkl'):
                        model_path = os.path.join(root, file)
                        break
        
        if not os.path.exists(preprocessor_path):
            for root, dirs, files in os.walk('data'):
                for file in files:
                    if 'preprocessor' in file.lower() and file.endswith('.pkl'):
                        preprocessor_path = os.path.join(root, file)
                        break
        
        capture_service = PacketCaptureService(model_path, preprocessor_path)
    
    return capture_service