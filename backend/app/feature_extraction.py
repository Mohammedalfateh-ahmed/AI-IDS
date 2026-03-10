import numpy as np

ATTACK_SIGNATURES = {
    'normal': [0, 1, 22, 10, 232, 8153, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 5, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 30, 255, 1.0, 0.0, 0.03, 0.04, 0.0, 0.0, 0.0, 0.0],
    'neptune': [0, 1, 20, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 511, 511, 1.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 255, 255, 1.0, 0.0, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0],
    'smurf': [0, 2, 11, 10, 1032, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 511, 511, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 255, 255, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0],
    'teardrop': [0, 2, 66, 10, 28, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1, 1, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    'pod': [0, 2, 11, 10, 1480, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 2, 2, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    'back': [0, 1, 22, 10, 54540, 8314, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 496, 496, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 255, 255, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    'land': [0, 1, 22, 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1, 1, 1.0, 0.0, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0],
    'portsweep': [0, 1, 50, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0.0, 0.0, 1.0, 1.0, 1.0, 0.0, 0.0, 25, 1, 0.04, 0.06, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0],
    'satan': [0, 1, 50, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0.0, 0.0, 1.0, 1.0, 0.5, 0.5, 0.0, 2, 1, 0.5, 0.5, 1.0, 0.0, 0.0, 0.0, 1.0, 1.0],
    'ipsweep': [0, 2, 11, 10, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 3, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.33, 255, 255, 1.0, 0.0, 1.0, 0.02, 0.0, 0.0, 0.0, 0.0],
    'nmap': [0, 1, 50, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0.0, 0.0, 1.0, 1.0, 1.0, 0.0, 0.0, 6, 6, 1.0, 0.0, 0.17, 0.17, 0.0, 0.0, 1.0, 1.0],
    'warezclient': [1, 1, 15, 10, 289, 2145, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 63, 10, 0.16, 0.03, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0],
    'guess_passwd': [0, 1, 25, 10, 105, 146, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 5, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 255, 6, 0.02, 0.07, 0.02, 0.0, 0.0, 0.0, 0.0, 0.0],
    'ftp_write': [1, 1, 15, 10, 200, 1500, 0, 0, 0, 2, 0, 1, 0, 0, 0, 0, 1, 0, 2, 0, 0, 0, 1, 1, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 255, 3, 0.01, 0.06, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    'imap': [0, 1, 24, 10, 200, 300, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 50, 10, 0.2, 0.05, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0],
    'buffer_overflow': [100, 1, 60, 10, 200, 300, 0, 0, 0, 3, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 3, 3, 1.0, 0.0, 0.33, 0.0, 0.0, 0.0, 0.0, 0.0],
    'rootkit': [200, 1, 60, 10, 300, 400, 0, 0, 0, 2, 0, 1, 2, 1, 1, 2, 2, 1, 3, 0, 0, 0, 1, 1, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1, 1, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    'loadmodule': [50, 1, 60, 10, 150, 200, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 2, 0, 0, 0, 1, 1, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 2, 2, 1.0, 0.0, 0.5, 0.0, 0.0, 0.0, 0.0, 0.0],
    'perl': [30, 1, 60, 10, 100, 150, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1, 1, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0]
}

ATTACK_CATEGORIES = {
    'neptune': 'DoS', 'smurf': 'DoS', 'teardrop': 'DoS', 'pod': 'DoS',
    'back': 'DoS', 'land': 'DoS', 'mailbomb': 'DoS', 'apache2': 'DoS',
    'processtable': 'DoS', 'udpstorm': 'DoS',
    'portsweep': 'Probe', 'satan': 'Probe', 'ipsweep': 'Probe', 'nmap': 'Probe',
    'mscan': 'Probe', 'saint': 'Probe',
    'warezclient': 'R2L', 'warezmaster': 'R2L', 'guess_passwd': 'R2L',
    'imap': 'R2L', 'ftp_write': 'R2L', 'multihop': 'R2L', 'phf': 'R2L',
    'spy': 'R2L', 'named': 'R2L', 'xlock': 'R2L', 'xsnoop': 'R2L',
    'sendmail': 'R2L', 'snmpgetattack': 'R2L', 'snmpguess': 'R2L',
    'buffer_overflow': 'U2R', 'rootkit': 'U2R', 'loadmodule': 'U2R',
    'perl': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R', 'ps': 'U2R',
    'normal': 'Normal'
}

def extract_features_from_packet(packet):
    features = np.array(ATTACK_SIGNATURES['normal'], dtype=float)
    return features.reshape(1, -1)

def generate_attack_features(attack_type):
    attack_type_lower = attack_type.lower().strip()
    
    if attack_type_lower in ATTACK_SIGNATURES:
        base_features = np.array(ATTACK_SIGNATURES[attack_type_lower], dtype=float)
    else:
        category = get_attack_category(attack_type_lower)
        if category == 'DoS':
            base_features = np.array(ATTACK_SIGNATURES['neptune'], dtype=float)
        elif category == 'Probe':
            base_features = np.array(ATTACK_SIGNATURES['portsweep'], dtype=float)
        elif category == 'R2L':
            base_features = np.array(ATTACK_SIGNATURES['warezclient'], dtype=float)
        elif category == 'U2R':
            base_features = np.array(ATTACK_SIGNATURES['buffer_overflow'], dtype=float)
        else:
            base_features = np.array(ATTACK_SIGNATURES['normal'], dtype=float)
    
    return base_features.reshape(1, -1)

def get_attack_category(attack_name):
    return ATTACK_CATEGORIES.get(attack_name.lower().strip(), 'Unknown')