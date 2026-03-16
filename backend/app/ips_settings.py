import json
from pathlib import Path

IPS_SETTINGS_FILE = Path("data/ips_settings.json")

DEFAULT_IPS_SETTINGS = {
    "ips_enabled": False,
    "auto_block_enabled": True,
    "whitelist_ips": ["127.0.0.1", "::1"],
    "block_duration_minutes": 0,
    "confidence_threshold": 0.85,
    "severity_threshold": "High",
    "auto_block_attacks": [
        "neptune", "smurf", "back", "teardrop", "pod", "land"
    ]
}

def load_ips_settings():
    IPS_SETTINGS_FILE.parent.mkdir(exist_ok=True)
    
    if not IPS_SETTINGS_FILE.exists():
        save_ips_settings(DEFAULT_IPS_SETTINGS)
        return DEFAULT_IPS_SETTINGS.copy()
    
    try:
        with open(IPS_SETTINGS_FILE, 'r') as f:
            return json.load(f)
    except:
        return DEFAULT_IPS_SETTINGS.copy()

def save_ips_settings(settings):
    IPS_SETTINGS_FILE.parent.mkdir(exist_ok=True)
    with open(IPS_SETTINGS_FILE, 'w') as f:
        json.dump(settings, f, indent=2)

def is_ips_enabled():
    settings = load_ips_settings()
    return settings.get("ips_enabled", False)

def is_ip_whitelisted(ip):
    settings = load_ips_settings()
    whitelist = settings.get("whitelist_ips", [])
    return ip in whitelist

def should_auto_block_with_ips(attack_type, confidence, severity):
    settings = load_ips_settings()
    
    if not settings.get("ips_enabled", False):
        return False
    
    if not settings.get("auto_block_enabled", True):
        return False
    
    if attack_type not in settings.get("auto_block_attacks", []):
        return False
    
    if confidence < settings.get("confidence_threshold", 0.85):
        return False
    
    severity_levels = ["Low", "Medium", "High", "Critical"]
    required_severity = settings.get("severity_threshold", "High")
    
    if severity not in severity_levels:
        return False
    
    required_index = severity_levels.index(required_severity)
    current_index = severity_levels.index(severity)
    
    return current_index >= required_index