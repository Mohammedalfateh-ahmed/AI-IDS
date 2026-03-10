ATTACK_DATABASE = {
    'neptune': {
        'name': 'Neptune SYN Flood Attack',
        'category': 'Denial of Service (DoS)',
        'severity': 'HIGH',
        'description': 'A SYN flood attack that exploits the TCP handshake by sending numerous SYN requests without completing the connection, exhausting server resources.',
        'attacker_method': [
            'Sends massive amounts of SYN packets to target',
            'Uses spoofed source IP addresses',
            'Never completes TCP three-way handshake',
            'Floods connection queue causing legitimate requests to fail'
        ],
        'indicators': [
            'Massive increase in half-open connections',
            'High volume of SYN packets',
            'Server becoming unresponsive',
            'Legitimate users unable to connect'
        ],
        'recommendations': [
            'Enable SYN cookies on your firewall',
            'Implement rate limiting for SYN packets',
            'Use connection timeout reduction',
            'Deploy DDoS mitigation service (CloudFlare, AWS Shield)',
            'Configure firewall rules: iptables -A INPUT -p tcp --syn -m limit --limit 1/s -j ACCEPT',
            'Increase backlog queue size on servers'
        ],
        'blocking_action': 'IMMEDIATE',
        'cvss_score': 7.5,
        'mitre_attack_id': 'T1498.001'
    },
    'smurf': {
        'name': 'Smurf ICMP Flood Attack',
        'category': 'Denial of Service (DoS)',
        'severity': 'HIGH',
        'description': 'A distributed denial-of-service attack that floods a victim with spoofed ICMP echo requests using an IP broadcast address.',
        'attacker_method': [
            'Sends ICMP echo requests to broadcast address',
            'Spoofs source IP to victim\'s address',
            'Amplifies attack through broadcast multiplication',
            'Overwhelms victim with ICMP replies'
        ],
        'indicators': [
            'High volume of ICMP echo replies',
            'Traffic from multiple sources simultaneously',
            'Network bandwidth saturation',
            'Increased latency and packet loss'
        ],
        'recommendations': [
            'Disable IP-directed broadcasts: no ip directed-broadcast',
            'Configure routers to ignore broadcast ICMP',
            'Implement ingress/egress filtering (BCP 38)',
            'Use anti-spoofing filters',
            'Rate-limit ICMP traffic on firewall',
            'Contact ISP for upstream filtering'
        ],
        'blocking_action': 'IMMEDIATE',
        'cvss_score': 7.0,
        'mitre_attack_id': 'T1498.002'
    },
    'portsweep': {
        'name': 'Port Sweep Reconnaissance',
        'category': 'Probe/Reconnaissance',
        'severity': 'MEDIUM',
        'description': 'Systematic probing of ports on a target system to identify open ports and running services, typically a precursor to more serious attacks.',
        'attacker_method': [
            'Scans multiple ports on target system',
            'Uses tools like Nmap or Masscan',
            'Identifies open ports and services',
            'Maps network topology and vulnerabilities'
        ],
        'indicators': [
            'Sequential connection attempts to multiple ports',
            'Short connection durations',
            'Failed connection attempts pattern',
            'Traffic from single source to many ports'
        ],
        'recommendations': [
            'Implement port knocking for sensitive services',
            'Use intrusion detection systems (Snort, Suricata)',
            'Enable detailed logging: iptables -A INPUT -j LOG --log-prefix "Port Scan: "',
            'Configure firewall to drop port scan attempts',
            'Hide service banners and version information',
            'Deploy fail2ban with portscan filter'
        ],
        'blocking_action': 'MONITOR',
        'cvss_score': 5.0,
        'mitre_attack_id': 'T1046'
    },
    'satan': {
        'name': 'SATAN Network Scanner',
        'category': 'Probe/Reconnaissance',
        'severity': 'MEDIUM',
        'description': 'Security Administrator Tool for Analyzing Networks - an automated reconnaissance tool that probes remote hosts for vulnerabilities.',
        'attacker_method': [
            'Performs automated vulnerability scanning',
            'Probes for common security weaknesses',
            'Tests for misconfigurations',
            'Identifies potential exploit targets'
        ],
        'indicators': [
            'Multiple service probes from single source',
            'Attempts to access known vulnerable services',
            'Pattern of reconnaissance activity',
            'Unusual service queries'
        ],
        'recommendations': [
            'Keep all systems and services updated',
            'Disable unnecessary services: systemctl disable <service>',
            'Implement network segmentation with VLANs',
            'Use vulnerability management tools (OpenVAS, Nessus)',
            'Enable rate limiting on sensitive services',
            'Deploy honeypots to detect scanners'
        ],
        'blocking_action': 'MONITOR',
        'cvss_score': 5.5,
        'mitre_attack_id': 'T1595'
    },
    'ipsweep': {
        'name': 'IP Address Sweep',
        'category': 'Probe/Reconnaissance',
        'severity': 'MEDIUM',
        'description': 'Systematic scanning of IP addresses to identify active hosts on a network, often used for network mapping before an attack.',
        'attacker_method': [
            'Pings multiple IP addresses sequentially',
            'Uses ICMP echo requests or TCP SYN',
            'Maps live hosts in network range',
            'Creates target list for further attacks'
        ],
        'indicators': [
            'Sequential ICMP requests to multiple IPs',
            'Single source scanning entire subnet',
            'Rapid connection attempts',
            'Pattern of host discovery activity'
        ],
        'recommendations': [
            'Configure firewalls to rate-limit ICMP',
            'Implement network access control (NAC)',
            'Use VLAN segmentation',
            'Deploy intrusion prevention systems',
            'Enable ICMP filtering: iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT',
            'Monitor for reconnaissance patterns'
        ],
        'blocking_action': 'MONITOR',
        'cvss_score': 4.5,
        'mitre_attack_id': 'T1595.001'
    },
    'back': {
        'name': 'Back Door Attack',
        'category': 'Remote to Local (R2L)',
        'severity': 'CRITICAL',
        'description': 'Exploitation of a backdoor or trojan to gain unauthorized access to a system, bypassing normal authentication.',
        'attacker_method': [
            'Exploits hidden access point in software',
            'Uses trojan or malware payload',
            'Bypasses authentication mechanisms',
            'Maintains persistent access'
        ],
        'indicators': [
            'Unexpected network connections',
            'Unknown processes running',
            'Unusual outbound traffic',
            'Unauthorized user accounts'
        ],
        'recommendations': [
            'Scan systems with anti-malware: rkhunter --check',
            'Implement application whitelisting',
            'Use endpoint detection and response (EDR)',
            'Review running processes: ps aux | grep -v root',
            'Monitor outbound connections: netstat -antp',
            'Check for persistence mechanisms in crontab and startup'
        ],
        'blocking_action': 'IMMEDIATE',
        'cvss_score': 9.0,
        'mitre_attack_id': 'T1543'
    },
    'warezclient': {
        'name': 'Warez Client Activity',
        'category': 'Remote to Local (R2L)',
        'severity': 'MEDIUM',
        'description': 'Unauthorized access attempts to download or distribute pirated software, potentially introducing malware.',
        'attacker_method': [
            'Attempts FTP/HTTP file transfers',
            'Accesses unauthorized file repositories',
            'Downloads potentially malicious files',
            'May include malware payloads'
        ],
        'indicators': [
            'Large data transfers to unknown servers',
            'Access to known warez sites',
            'Unusual FTP activity',
            'Policy violations in web logs'
        ],
        'recommendations': [
            'Implement web filtering and DLP',
            'Monitor and block known warez sites',
            'Enforce acceptable use policies',
            'Deploy endpoint security solutions',
            'Block unauthorized FTP: iptables -A OUTPUT -p tcp --dport 21 -j DROP',
            'Implement network access controls'
        ],
        'blocking_action': 'BLOCK',
        'cvss_score': 6.0,
        'mitre_attack_id': 'T1071'
    },
    'teardrop': {
        'name': 'Teardrop Fragment Attack',
        'category': 'Denial of Service (DoS)',
        'severity': 'HIGH',
        'description': 'Sends mangled IP fragments with overlapping offsets causing the target system to crash when trying to reassemble them.',
        'attacker_method': [
            'Creates malformed IP packet fragments',
            'Sends overlapping fragment offsets',
            'Exploits IP reassembly vulnerabilities',
            'Causes system crash or freeze'
        ],
        'indicators': [
            'Malformed packet fragments detected',
            'System instability or crashes',
            'IP reassembly errors in logs',
            'Unexpected system reboots'
        ],
        'recommendations': [
            'Apply latest OS security patches immediately',
            'Enable fragment reassembly protection',
            'Configure firewalls: iptables -A INPUT -f -j DROP',
            'Use intrusion prevention systems',
            'Implement packet validation',
            'Keep network equipment firmware updated'
        ],
        'blocking_action': 'IMMEDIATE',
        'cvss_score': 7.5,
        'mitre_attack_id': 'T1499.001'
    },
    'pod': {
        'name': 'Ping of Death (PoD)',
        'category': 'Denial of Service (DoS)',
        'severity': 'HIGH',
        'description': 'Sends oversized ping packets (>65,535 bytes) causing buffer overflow and system crash on vulnerable systems.',
        'attacker_method': [
            'Creates oversized ICMP packets',
            'Fragments packets to bypass size checks',
            'Causes buffer overflow on reassembly',
            'Crashes or freezes target system'
        ],
        'indicators': [
            'Oversized ICMP packets detected',
            'Fragmented ping packets',
            'System crashes after ping activity',
            'Buffer overflow errors'
        ],
        'recommendations': [
            'Update operating systems with PoD patches',
            'Configure firewalls: iptables -A INPUT -p icmp --icmp-type echo-request -m length --length 1:84 -j ACCEPT',
            'Implement packet size validation',
            'Use modern OS (most are patched)',
            'Enable ICMP rate limiting',
            'Deploy network intrusion detection'
        ],
        'blocking_action': 'IMMEDIATE',
        'cvss_score': 7.0,
        'mitre_attack_id': 'T1499.004'
    }
}

def get_attack_info(attack_type):
    attack_type_lower = attack_type.lower()
    
    if attack_type_lower in ATTACK_DATABASE:
        return ATTACK_DATABASE[attack_type_lower]
    
    return {
        'name': f'Unknown Attack: {attack_type}',
        'category': 'Unknown',
        'severity': 'MEDIUM',
        'description': 'This attack type is not yet documented in the threat intelligence database.',
        'attacker_method': ['Pattern analysis in progress...'],
        'indicators': ['Unusual network activity detected'],
        'recommendations': [
            'Monitor the source IP closely',
            'Review system logs for anomalies',
            'Update threat intelligence database',
            'Consult with security team'
        ],
        'blocking_action': 'MONITOR',
        'cvss_score': 5.0,
        'mitre_attack_id': 'N/A'
    }

def should_auto_block(attack_type, confidence):
    info = get_attack_info(attack_type)
    
    if info['blocking_action'] == 'IMMEDIATE' and confidence > 0.8:
        return True
    
    return False

def get_prediction_analysis(recent_alerts):
    if not recent_alerts or len(recent_alerts) < 3:
        return {
            'prediction': 'Insufficient data for pattern analysis',
            'confidence': 0.0,
            'next_likely_attack': 'Unknown',
            'time_window': 'N/A',
            'pattern': 'Need at least 3 alerts for analysis'
        }
    
    attack_types = {}
    source_ips = {}
    
    for alert in recent_alerts:
        attack_type = alert.get('attack_type', 'unknown')
        source_ip = alert.get('source_ip', 'unknown')
        
        attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        source_ips[source_ip] = source_ips.get(source_ip, 0) + 1
    
    most_common_attack = max(attack_types.items(), key=lambda x: x[1])
    most_common_ip = max(source_ips.items(), key=lambda x: x[1])
    
    confidence = min(0.95, (most_common_attack[1] / len(recent_alerts)) * 1.2)
    
    return {
        'prediction': f'High probability of continued {most_common_attack[0]} attacks',
        'confidence': round(confidence, 2),
        'next_likely_attack': most_common_attack[0],
        'time_window': 'Next 5-10 minutes',
        'pattern': f'Detected {most_common_attack[1]} {most_common_attack[0]} attacks from {most_common_ip[0]}',
        'threat_level': 'HIGH' if confidence > 0.7 else 'MEDIUM',
        'attack_count': most_common_attack[1],
        'unique_sources': len(source_ips)
    }