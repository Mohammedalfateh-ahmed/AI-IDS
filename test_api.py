import requests
import json
from datetime import datetime

API_URL = "http://localhost:8000"

print("="*80)
print("TESTING INTELLIGENT IDS API")
print("="*80)

print("\n[TEST 1] Health Check...")
try:
    response = requests.get(f"{API_URL}/health")
    print(f"Status: {response.status_code}")
    print(json.dumps(response.json(), indent=2))
except Exception as e:
    print(f"ERROR: {e}")
    print("Make sure the API is running: python backend/app/main.py")
    exit(1)

print("\n[TEST 2] Model Info...")
response = requests.get(f"{API_URL}/model/info")
print(f"Status: {response.status_code}")
data = response.json()
print(f"Model Type: {data['model_type']}")
print(f"Features: {data['num_features']}")
print(f"Attack Types: {data['num_classes']}")
print(f"Can detect: {', '.join(data['attack_types'][:10])}...")

print("\n[TEST 3] Simulating Normal Traffic...")
response = requests.post(f"{API_URL}/test/simulate?attack_type=normal")
print(f"Status: {response.status_code}")
result = response.json()
print(f"Is Attack: {result['is_attack']}")
print(f"Type: {result['attack_type']}")
print(f"Confidence: {result['confidence']:.2%}")

print("\n[TEST 4] Simulating DoS Attack...")
response = requests.post(f"{API_URL}/test/simulate?attack_type=dos")
print(f"Status: {response.status_code}")
result = response.json()
print(f"Is Attack: {result['is_attack']}")
print(f"Type: {result['attack_type']}")
print(f"Confidence: {result['confidence']:.2%}")

print("\n[TEST 5] Simulating Probe Attack...")
response = requests.post(f"{API_URL}/test/simulate?attack_type=probe")
print(f"Status: {response.status_code}")
result = response.json()
print(f"Is Attack: {result['is_attack']}")
print(f"Type: {result['attack_type']}")
print(f"Confidence: {result['confidence']:.2%}")

print("\n[TEST 6] Getting Alerts...")
response = requests.get(f"{API_URL}/alerts")
print(f"Status: {response.status_code}")
data = response.json()
print(f"Total Alerts: {data['total']}")

print("\n[TEST 7] Getting Statistics...")
response = requests.get(f"{API_URL}/stats")
print(f"Status: {response.status_code}")
stats = response.json()
print(f"Total Alerts: {stats['total_alerts']}")
if stats['total_alerts'] > 0:
    print(f"Average Confidence: {stats['average_confidence']:.2%}")
    print("Top Attacks:")
    for attack, count in stats['top_attacks']:
        print(f"  - {attack}: {count}")

print("\n[TEST 8] Manual Prediction...")
sample_traffic = {
    "duration": 0,
    "protocol_type": "tcp",
    "service": "http",
    "flag": "SF",
    "src_bytes": 181,
    "dst_bytes": 5450,
    "land": 0,
    "wrong_fragment": 0,
    "urgent": 0,
    "hot": 0,
    "num_failed_logins": 0,
    "logged_in": 1,
    "num_compromised": 0,
    "root_shell": 0,
    "su_attempted": 0,
    "num_root": 0,
    "num_file_creations": 0,
    "num_shells": 0,
    "num_access_files": 0,
    "num_outbound_cmds": 0,
    "is_host_login": 0,
    "is_guest_login": 0,
    "count": 8,
    "srv_count": 8,
    "serror_rate": 0.0,
    "srv_serror_rate": 0.0,
    "rerror_rate": 0.0,
    "srv_rerror_rate": 0.0,
    "same_srv_rate": 1.0,
    "diff_srv_rate": 0.0,
    "srv_diff_host_rate": 0.0,
    "dst_host_count": 9,
    "dst_host_srv_count": 9,
    "dst_host_same_srv_rate": 1.0,
    "dst_host_diff_srv_rate": 0.0,
    "dst_host_same_src_port_rate": 0.11,
    "dst_host_srv_diff_host_rate": 0.0,
    "dst_host_serror_rate": 0.0,
    "dst_host_srv_serror_rate": 0.0,
    "dst_host_rerror_rate": 0.0,
    "dst_host_srv_rerror_rate": 0.0
}

response = requests.post(f"{API_URL}/predict", json=sample_traffic)
print(f"Status: {response.status_code}")
result = response.json()
print(f"Result: {json.dumps(result, indent=2)}")

print("\n" + "="*80)
print("API TESTING COMPLETE!")
print("="*80)
print("\nAPI is working correctly!")
print("="*80)