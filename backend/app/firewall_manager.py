import subprocess
import json
import os
from datetime import datetime, timedelta
from pathlib import Path

class FirewallManager:
    def __init__(self):
        self.blocked_ips_file = Path("data/blocked_ips.json")
        self.whitelist_file = Path("data/whitelist.json")
        self.blocked_ips_file.parent.mkdir(exist_ok=True)
        self.load_data()
    
    def load_data(self):
        if self.blocked_ips_file.exists():
            with open(self.blocked_ips_file, 'r') as f:
                self.blocked_ips = json.load(f)
        else:
            self.blocked_ips = {}
        
        if self.whitelist_file.exists():
            with open(self.whitelist_file, 'r') as f:
                self.whitelist = json.load(f)
        else:
            self.whitelist = ["127.0.0.1", "::1", "192.168.1.1"]
    
    def save_data(self):
        with open(self.blocked_ips_file, 'w') as f:
            json.dump(self.blocked_ips, f, indent=2)
        
        with open(self.whitelist_file, 'w') as f:
            json.dump(self.whitelist, f, indent=2)
    
    def is_whitelisted(self, ip):
        return ip in self.whitelist
    
    def block_ip(self, ip, reason, duration_minutes=60):
        if self.is_whitelisted(ip):
            return {"status": "skipped", "reason": "IP is whitelisted"}
        
        if ip in self.blocked_ips:
            return {"status": "already_blocked", "reason": "IP already blocked"}
        
        rule_name = f"IDS_Block_{ip.replace('.', '_').replace(':', '_')}"
        
        try:
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                block_time = datetime.now().isoformat()
                unblock_time = (datetime.now() + timedelta(minutes=duration_minutes)).isoformat()
                
                self.blocked_ips[ip] = {
                    "rule_name": rule_name,
                    "blocked_at": block_time,
                    "unblock_at": unblock_time,
                    "reason": reason,
                    "duration_minutes": duration_minutes
                }
                self.save_data()
                
                return {"status": "success", "message": f"IP {ip} blocked successfully"}
            else:
                return {"status": "error", "message": result.stderr}
        
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def unblock_ip(self, ip):
        if ip not in self.blocked_ips:
            return {"status": "not_blocked", "message": "IP is not blocked"}
        
        rule_name = self.blocked_ips[ip]["rule_name"]
        
        try:
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                del self.blocked_ips[ip]
                self.save_data()
                return {"status": "success", "message": f"IP {ip} unblocked successfully"}
            else:
                return {"status": "error", "message": result.stderr}
        
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def check_expired_blocks(self):
        now = datetime.now()
        expired_ips = []
        
        for ip, data in self.blocked_ips.items():
            unblock_time = datetime.fromisoformat(data["unblock_at"])
            if now >= unblock_time:
                expired_ips.append(ip)
        
        results = []
        for ip in expired_ips:
            result = self.unblock_ip(ip)
            results.append({"ip": ip, "result": result})
        
        return results
    
    def get_blocked_ips(self):
        return self.blocked_ips
    
    def add_to_whitelist(self, ip):
        if ip not in self.whitelist:
            self.whitelist.append(ip)
            self.save_data()
            return {"status": "success", "message": f"IP {ip} added to whitelist"}
        return {"status": "already_exists", "message": "IP already in whitelist"}
    
    def remove_from_whitelist(self, ip):
        if ip in self.whitelist:
            self.whitelist.remove(ip)
            self.save_data()
            return {"status": "success", "message": f"IP {ip} removed from whitelist"}
        return {"status": "not_found", "message": "IP not in whitelist"}
    
    def get_whitelist(self):
        return self.whitelist
    
    def unblock_all(self):
        results = []
        ips_to_unblock = list(self.blocked_ips.keys())
        
        for ip in ips_to_unblock:
            result = self.unblock_ip(ip)
            results.append({"ip": ip, "result": result})
        
        return results