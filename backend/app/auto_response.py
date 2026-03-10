import threading
import time
from datetime import datetime

class AutoResponseHandler:
    def __init__(self, firewall_manager, alert_store):
        self.firewall_manager = firewall_manager
        self.alert_store = alert_store
        self.enabled = True
        self.confidence_threshold = 0.7
        self.block_duration = 60
        self.monitor_thread = None
        self.attack_count = {}
        self.attack_threshold = 3
    
    def start_monitoring(self):
        if self.monitor_thread and self.monitor_thread.is_alive():
            return {"status": "already_running"}
        
        self.enabled = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        return {"status": "success", "message": "Auto-response monitoring started"}
    
    def stop_monitoring(self):
        self.enabled = False
        return {"status": "success", "message": "Auto-response monitoring stopped"}
    
    def _monitor_loop(self):
        while self.enabled:
            self.firewall_manager.check_expired_blocks()
            time.sleep(30)
    
    def process_attack(self, alert):
        if not self.enabled:
            return {"status": "disabled"}
        
        confidence = alert.get("confidence", 0)
        if confidence < self.confidence_threshold:
            return {"status": "low_confidence"}
        
        ip = alert.get("source_ip", "unknown")
        if ip == "unknown" or ip == "127.0.0.1":
            return {"status": "invalid_ip"}
        
        if ip not in self.attack_count:
            self.attack_count[ip] = 0
        
        self.attack_count[ip] += 1
        
        if self.attack_count[ip] >= self.attack_threshold:
            attack_type = alert.get("attack_type", "Unknown")
            reason = f"Multiple attacks detected: {attack_type} (Count: {self.attack_count[ip]})"
            
            result = self.firewall_manager.block_ip(ip, reason, self.block_duration)
            
            if result["status"] == "success":
                self.attack_count[ip] = 0
                
                self.alert_store.append({
                    "timestamp": datetime.now().isoformat(),
                    "type": "IP_BLOCKED",
                    "ip": ip,
                    "reason": reason,
                    "duration": self.block_duration
                })
            
            return result
        
        return {"status": "threshold_not_met", "count": self.attack_count[ip]}
    
    def set_config(self, confidence_threshold=None, block_duration=None, attack_threshold=None):
        if confidence_threshold is not None:
            self.confidence_threshold = confidence_threshold
        if block_duration is not None:
            self.block_duration = block_duration
        if attack_threshold is not None:
            self.attack_threshold = attack_threshold
        
        return {
            "confidence_threshold": self.confidence_threshold,
            "block_duration": self.block_duration,
            "attack_threshold": self.attack_threshold
        }
    
    def get_config(self):
        return {
            "enabled": self.enabled,
            "confidence_threshold": self.confidence_threshold,
            "block_duration": self.block_duration,
            "attack_threshold": self.attack_threshold
        }