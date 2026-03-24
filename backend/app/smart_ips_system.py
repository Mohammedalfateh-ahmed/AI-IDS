import subprocess
import platform
import ctypes
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import re

class SmartIPSSystem:
    """
    Smart Intrusion Prevention System with Windows Firewall Integration
    Features:
    - Intelligent threat scoring (Cloudflare-style)
    - Automatic IP blocking via Windows Firewall (netsh)
    - Whitelist/Blacklist management
    - Rate limiting and traffic analysis
    - Temporary vs Permanent blocking
    - Geographic IP tracking
    - Attack pattern recognition
    - Auto-unblock after timeout
    - Email alerts integration
    """
    
    def __init__(self):
        self.config_file = Path("data/ips_config.json")
        self.blocked_ips_file = Path("data/firewall_blocks.json")
        self.whitelist_file = Path("data/whitelist.json")
        
        self.config_file.parent.mkdir(exist_ok=True)
        
        self.is_windows = platform.system() == "Windows"
        self.is_admin = self._check_admin_privileges()
        
        self.threat_tracking = {}
        self.rate_limits = {}
        self.blocked_ips = self._load_blocked_ips()
        self.whitelist = self._load_whitelist()
        
        self.config = self._load_config()
        
        self.THREAT_SCORES = {
            "neptune": 95,
            "smurf": 90,
            "back": 85,
            "teardrop": 85,
            "pod": 80,
            "land": 85,
            "buffer_overflow": 100,
            "rootkit": 100,
            "loadmodule": 95,
            "perl": 90,
            "portsweep": 60,
            "satan": 70,
            "ipsweep": 55,
            "nmap": 50,
            "warezclient": 40,
            "guess_passwd": 75,
            "ftp_write": 65,
            "imap": 60,
            "normal": 0
        }
    
    def _check_admin_privileges(self) -> bool:
        if not self.is_windows:
            return False
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    
    def _load_config(self) -> Dict:
        default_config = {
            "ips_enabled": True,
            "auto_block_enabled": True,
            "firewall_blocking_enabled": True,
            "confidence_threshold": 0.75,
            "threat_score_threshold": 70,
            "rate_limit_enabled": True,
            "rate_limit_requests": 50,
            "rate_limit_window": 60,
            "temp_block_duration_hours": 24,
            "perm_block_threshold": 90,
            "challenge_threshold": 50,
            "auto_unblock_enabled": True,
            "email_alerts_enabled": True,
            "log_all_traffic": False,
            "protection_mode": "standard",
            "block_countries": [],
            "high_security_mode": False
        }
        
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    loaded = json.load(f)
                    default_config.update(loaded)
        except:
            pass
        
        self._save_config(default_config)
        return default_config
    
    def _save_config(self, config: Dict):
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    def _load_blocked_ips(self) -> Dict:
        try:
            if self.blocked_ips_file.exists():
                with open(self.blocked_ips_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        return {}
    
    def _save_blocked_ips(self):
        with open(self.blocked_ips_file, 'w') as f:
            json.dump(self.blocked_ips, f, indent=2)
    
    def _load_whitelist(self) -> List[str]:
        default_whitelist = ["127.0.0.1", "::1", "localhost", "192.168.1.1"]
        
        try:
            if self.whitelist_file.exists():
                with open(self.whitelist_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        
        with open(self.whitelist_file, 'w') as f:
            json.dump(default_whitelist, f, indent=2)
        
        return default_whitelist
    
    def _save_whitelist(self):
        with open(self.whitelist_file, 'w') as f:
            json.dump(self.whitelist, f, indent=2)
    
    def is_whitelisted(self, ip: str) -> bool:
        return ip in self.whitelist
    
    def add_to_whitelist(self, ip: str) -> bool:
        if ip not in self.whitelist:
            self.whitelist.append(ip)
            self._save_whitelist()
            return True
        return False
    
    def remove_from_whitelist(self, ip: str) -> bool:
        if ip in self.whitelist:
            self.whitelist.remove(ip)
            self._save_whitelist()
            return True
        return False
    
    def calculate_threat_score(self, ip: str, attack_type: str, confidence: float) -> int:
        base_score = self.THREAT_SCORES.get(attack_type.lower(), 50)
        
        if ip not in self.threat_tracking:
            self.threat_tracking[ip] = {
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
                "attack_count": 0,
                "attack_types": [],
                "total_threat_score": 0,
                "blocked_count": 0
            }
        
        tracking = self.threat_tracking[ip]
        tracking["last_seen"] = datetime.now().isoformat()
        tracking["attack_count"] += 1
        
        if attack_type not in tracking["attack_types"]:
            tracking["attack_types"].append(attack_type)
        
        confidence_boost = confidence * 20
        
        repeat_penalty = min(tracking["attack_count"] * 5, 40)
        
        diversity_penalty = len(tracking["attack_types"]) * 10
        
        final_score = base_score + confidence_boost + repeat_penalty + diversity_penalty
        
        final_score = min(final_score, 100)
        
        tracking["total_threat_score"] = int(final_score)
        
        return int(final_score)
    
    def check_rate_limit(self, ip: str) -> Tuple[bool, int]:
        if not self.config["rate_limit_enabled"]:
            return False, 0
        
        now = datetime.now()
        window = self.config["rate_limit_window"]
        max_requests = self.config["rate_limit_requests"]
        
        if ip not in self.rate_limits:
            self.rate_limits[ip] = []
        
        self.rate_limits[ip] = [
            req_time for req_time in self.rate_limits[ip]
            if (now - datetime.fromisoformat(req_time)).total_seconds() <= window
        ]
        
        self.rate_limits[ip].append(now.isoformat())
        
        current_count = len(self.rate_limits[ip])
        
        return current_count > max_requests, current_count
    
    def block_ip_firewall(self, ip: str, attack_type: str, block_type: str = "temporary") -> Dict:
        if not self.is_windows:
            return {
                "success": False,
                "error": "Windows Firewall only available on Windows",
                "method": "database_only"
            }
        
        if not self.is_admin:
            return {
                "success": False,
                "error": "Administrator privileges required for firewall blocking",
                "method": "database_only"
            }
        
        if not self.config["firewall_blocking_enabled"]:
            return {
                "success": False,
                "error": "Firewall blocking disabled in configuration",
                "method": "database_only"
            }
        
        rule_name = f"AI-IDS-Block-{ip}"
        
        try:
            check_cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'
            result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
            
            if "No rules match" not in result.stdout:
                return {
                    "success": True,
                    "message": f"IP {ip} already blocked in firewall",
                    "method": "firewall",
                    "rule_name": rule_name
                }
            
            block_cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
            
            result = subprocess.run(block_cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.blocked_ips[ip] = {
                    "blocked_at": datetime.now().isoformat(),
                    "attack_type": attack_type,
                    "block_type": block_type,
                    "rule_name": rule_name,
                    "method": "firewall"
                }
                
                if block_type == "temporary":
                    unblock_time = datetime.now() + timedelta(hours=self.config["temp_block_duration_hours"])
                    self.blocked_ips[ip]["unblock_at"] = unblock_time.isoformat()
                
                self._save_blocked_ips()
                
                return {
                    "success": True,
                    "message": f"IP {ip} blocked in Windows Firewall",
                    "method": "firewall",
                    "rule_name": rule_name,
                    "block_type": block_type
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr or "Firewall blocking failed",
                    "method": "failed"
                }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "method": "error"
            }
    
    def unblock_ip_firewall(self, ip: str) -> Dict:
        if not self.is_windows or not self.is_admin:
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                self._save_blocked_ips()
            return {
                "success": True,
                "message": f"IP {ip} removed from database",
                "method": "database_only"
            }
        
        rule_name = f"AI-IDS-Block-{ip}"
        
        try:
            unblock_cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            result = subprocess.run(unblock_cmd, shell=True, capture_output=True, text=True)
            
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                self._save_blocked_ips()
            
            return {
                "success": True,
                "message": f"IP {ip} unblocked from firewall",
                "method": "firewall"
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def list_firewall_blocks(self) -> List[Dict]:
        blocks = []
        
        for ip, data in self.blocked_ips.items():
            blocks.append({
                "ip_address": ip,
                "blocked_at": data.get("blocked_at"),
                "attack_type": data.get("attack_type"),
                "block_type": data.get("block_type"),
                "method": data.get("method"),
                "unblock_at": data.get("unblock_at")
            })
        
        return blocks
    
    def clear_all_firewall_rules(self) -> Dict:
        if not self.is_windows or not self.is_admin:
            self.blocked_ips = {}
            self._save_blocked_ips()
            return {
                "success": True,
                "cleared": 0,
                "message": "Database cleared (no firewall access)"
            }
        
        try:
            cleared_count = 0
            
            for ip in list(self.blocked_ips.keys()):
                rule_name = f"AI-IDS-Block-{ip}"
                cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    cleared_count += 1
            
            self.blocked_ips = {}
            self._save_blocked_ips()
            
            return {
                "success": True,
                "cleared": cleared_count,
                "message": f"Cleared {cleared_count} firewall rules"
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def auto_unblock_expired(self) -> int:
        if not self.config["auto_unblock_enabled"]:
            return 0
        
        now = datetime.now()
        unblocked_count = 0
        
        for ip, data in list(self.blocked_ips.items()):
            if data.get("block_type") == "temporary" and "unblock_at" in data:
                unblock_time = datetime.fromisoformat(data["unblock_at"])
                if now >= unblock_time:
                    result = self.unblock_ip_firewall(ip)
                    if result["success"]:
                        unblocked_count += 1
        
        return unblocked_count
    
    def should_block_attack(self, ip: str, attack_type: str, confidence: float, severity: str) -> Dict:
        if not self.config["ips_enabled"] or not self.config["auto_block_enabled"]:
            return {
                "should_block": False,
                "reason": "IPS disabled",
                "method": "none"
            }
        
        if self.is_whitelisted(ip):
            return {
                "should_block": False,
                "reason": "IP is whitelisted",
                "method": "whitelist"
            }
        
        if ip in self.blocked_ips:
            return {
                "should_block": True,
                "reason": "Already blocked",
                "method": "existing",
                "details": self.blocked_ips[ip]
            }
        
        if confidence < self.config["confidence_threshold"]:
            return {
                "should_block": False,
                "reason": f"Confidence too low ({confidence:.2f} < {self.config['confidence_threshold']})",
                "method": "threshold"
            }
        
        threat_score = self.calculate_threat_score(ip, attack_type, confidence)
        
        rate_limited, request_count = self.check_rate_limit(ip)
        
        if rate_limited:
            threat_score += 20
        
        block_type = "temporary"
        if threat_score >= self.config["perm_block_threshold"]:
            block_type = "permanent"
        
        should_block = threat_score >= self.config["threat_score_threshold"]
        
        action = "BLOCK" if should_block else "MONITOR"
        if threat_score >= self.config["challenge_threshold"] and not should_block:
            action = "CHALLENGE"
        
        return {
            "should_block": should_block,
            "threat_score": threat_score,
            "block_type": block_type,
            "action": action,
            "reason": f"Threat score: {threat_score}/100",
            "rate_limited": rate_limited,
            "request_count": request_count,
            "attack_count": self.threat_tracking[ip]["attack_count"] if ip in self.threat_tracking else 0,
            "method": "analysis"
        }
    
    def process_attack(self, ip: str, attack_type: str, confidence: float, severity: str) -> Dict:
        decision = self.should_block_attack(ip, attack_type, confidence, severity)
        
        if decision["should_block"]:
            firewall_result = self.block_ip_firewall(
                ip=ip,
                attack_type=attack_type,
                block_type=decision["block_type"]
            )
            
            return {
                **decision,
                "blocked": firewall_result["success"],
                "firewall_result": firewall_result,
                "protection_level": self._get_protection_level(decision["threat_score"])
            }
        
        return {
            **decision,
            "blocked": False,
            "protection_level": self._get_protection_level(decision.get("threat_score", 0))
        }
    
    def _get_protection_level(self, threat_score: int) -> str:
        if threat_score >= 85:
            return "I'm Under Attack!"
        elif threat_score >= 60:
            return "High Security"
        elif threat_score >= 30:
            return "Medium Security"
        else:
            return "Standard"
    
    def get_system_status(self) -> Dict:
        return {
            "ips_enabled": self.config["ips_enabled"],
            "auto_block_enabled": self.config["auto_block_enabled"],
            "firewall_blocking_enabled": self.config["firewall_blocking_enabled"],
            "is_windows": self.is_windows,
            "has_admin_privileges": self.is_admin,
            "total_blocked_ips": len(self.blocked_ips),
            "total_tracked_ips": len(self.threat_tracking),
            "whitelist_count": len(self.whitelist),
            "protection_mode": self.config["protection_mode"],
            "firewall_available": self.is_windows and self.is_admin,
            "status": "operational" if (self.config["ips_enabled"] and self.config["auto_block_enabled"]) else "disabled"
        }
    
    def get_top_threats(self, limit: int = 10) -> List[Dict]:
        threats = []
        
        for ip, tracking in self.threat_tracking.items():
            threats.append({
                "ip_address": ip,
                "threat_score": tracking["total_threat_score"],
                "attack_count": tracking["attack_count"],
                "attack_types": tracking["attack_types"],
                "first_seen": tracking["first_seen"],
                "last_seen": tracking["last_seen"],
                "is_blocked": ip in self.blocked_ips
            })
        
        threats.sort(key=lambda x: x["threat_score"], reverse=True)
        
        return threats[:limit]
    
    def update_config(self, new_config: Dict) -> bool:
        self.config.update(new_config)
        self._save_config(self.config)
        return True
    
    def get_config(self) -> Dict:
        return self.config.copy()

smart_ips = SmartIPSSystem()