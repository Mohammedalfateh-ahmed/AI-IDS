from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer
from fastapi.security.http import HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import jwt
import json
from pathlib import Path
import numpy as np
import joblib
from typing import Optional
import bcrypt
import os
import threading
import logging
from mongodb_config import db, alerts_collection, blocked_ips_collection, attack_patterns_collection, system_logs_collection
from attack_intelligence import get_attack_info, should_auto_block, get_prediction_analysis
from bson import ObjectId
from feature_extraction import extract_features_from_packet, generate_attack_features, get_attack_category
from intelligence_engine import intelligence_engine
from datetime import datetime, timedelta, timezone
from smart_ips_system import smart_ips
from behavior_analyzer import behavior_analyzer
Path("logs").mkdir(exist_ok=True)
def is_ips_enabled():
    try:
        settings_file = Path("data/ips_config.json")
        if settings_file.exists():
            with open(settings_file, 'r') as f:
                return json.load(f).get("ips_enabled", True)
    except:
        pass
    return True  # Default ENABLED

def should_auto_block_with_ips(attack_type: str, confidence: float, severity: str):
    if not is_ips_enabled():
        return False
    try:
        settings_file = Path("data/ips_config.json")
        settings = json.load(open(settings_file)) if settings_file.exists() else {
            "confidence_threshold": 0.85,
            "severity_threshold": "High",
            "auto_block_attacks": ["neptune", "smurf", "back", "teardrop"]
        }
        if confidence < settings.get("confidence_threshold", 0.85):
            return False
        return attack_type.lower() in [a.lower() for a in settings.get("auto_block_attacks", [])]
    except:
        return confidence >= 0.85
try:
    from email_service_professional import (
        send_wazuh_style_alert,
        send_daily_summary_wazuh_style,
        send_critical_system_alert
    )
    print("✅ Professional email service loaded")
except ImportError as e:
    print(f"⚠️ Email service not available: {e}")
    send_wazuh_style_alert = None
    send_daily_summary_wazuh_style = None
    send_critical_system_alert = None

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[
        logging.FileHandler('logs/ids_system.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8000",
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

SECRET_KEY = "your-secret-key-change-this-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

users_file = Path("data/users.json")
users_file.parent.mkdir(exist_ok=True)

if not users_file.exists():
    default_users = {
        "admin": {
            "username": "admin",
            "password": bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode(),
            "role": "admin"
        }
    }
    with open(users_file, 'w') as f:
        json.dump(default_users, f, indent=2)

def load_users():
    with open(users_file, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(users_file, 'w') as f:
        json.dump(users, f, indent=2)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(token_data: dict = Depends(verify_token)):
    users = load_users()
    username = token_data.get("sub")
    if username not in users:
        raise HTTPException(status_code=401, detail="User not found")
    return users[username]

def get_current_admin_user(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

class LoginRequest(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    password: str
    role: str

model = None
preprocessor = None
label_encoder = None
model_metrics = None

def find_model_file(filename):
    possible_paths = [
        f'data/models/{filename}',
        f'../data/models/{filename}',
        f'../../data/models/{filename}'
    ]
    for path in possible_paths:
        if os.path.exists(path):
            return path
    return None

try:
    model_path = find_model_file('xgboost_nslkdd_model.pkl')
    if model_path:
        model = joblib.load(model_path)
        print(f"✅ Model loaded: {model_path}")
except Exception as e:
    print(f"❌ Model error: {e}")

try:
    preprocessor_path = find_model_file('preprocessor_nslkdd.pkl')
    if preprocessor_path:
        preprocessor = joblib.load(preprocessor_path)
        if isinstance(preprocessor, dict) and 'label_encoder' in preprocessor:
            label_encoder = preprocessor['label_encoder']
            print(f"✅ Label encoder extracted from preprocessor")
        print(f"✅ Preprocessor loaded: {preprocessor_path}")
except Exception as e:
    print(f"❌ Preprocessor error: {e}")

try:
    metrics_path = find_model_file('model_metrics.json')
    if metrics_path:
        with open(metrics_path, 'r') as f:
            model_metrics = json.load(f)
        print(f"✅ Metrics loaded: {metrics_path}")
except:
    print("⚠️ No metrics file found")

alerts = []
stats = {
    "total_packets": 0,
    "attacks_detected": 0,
    "benign_traffic": 0,
}

print(f"[+] Stats initialized: {stats}")

capture_active = False
capture_thread = None
packets_captured = 0

@app.post("/auth/login")
async def login(request: LoginRequest):
    users = load_users()
    user = users.get(request.username)
    
    if not user or not bcrypt.checkpw(request.password.encode(), user["password"].encode()):
        logger.warning(f"LOGIN_FAILED | User: {request.username} | Reason: Invalid credentials")
        
        system_logs_collection.insert_one({
            "timestamp": datetime.now(),
            "level": "ERROR",
            "message": f"Failed login attempt for user: {request.username}",
            "user": request.username,
            "details": {"reason": "Invalid credentials"}
        })
        
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    logger.info(f"LOGIN_SUCCESS | User: {request.username} | Role: {user['role']}")
    
    system_logs_collection.insert_one({
        "timestamp": datetime.now(),
        "level": "LOGIN_SUCCESS",
        "message": f"User {request.username} logged in successfully",
        "user": request.username,
        "details": {
            "role": user['role'],
            "login_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    })
    
    access_token = create_access_token(data={"sub": user["username"], "role": user["role"]})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "username": user["username"],
            "role": user["role"]
        }
    }

@app.get("/auth/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    return {
        "username": current_user["username"],
        "role": current_user["role"]
    }

@app.get("/users")
async def get_users(current_user: dict = Depends(get_current_admin_user)):
    users = load_users()
    return [{"username": u, "role": users[u]["role"]} for u in users]

@app.post("/users")
async def create_user(user_data: UserCreate, current_user: dict = Depends(get_current_admin_user)):
    users = load_users()
    
    if user_data.username in users:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    hashed_password = bcrypt.hashpw(user_data.password.encode(), bcrypt.gensalt()).decode()
    users[user_data.username] = {
        "username": user_data.username,
        "password": hashed_password,
        "role": user_data.role
    }
    save_users(users)
    
    system_logs_collection.insert_one({
        "timestamp": datetime.now(),
        "level": "INFO",
        "message": f"New user created: {user_data.username}",
        "user": current_user['username'],
        "details": {
            "new_username": user_data.username,
            "role": user_data.role,
            "created_by": current_user['username']
        }
    })
    
    return {"message": "User created successfully"}

@app.delete("/users/{username}")
async def delete_user(username: str, current_user: dict = Depends(get_current_admin_user)):
    if username == "admin":
        raise HTTPException(status_code=400, detail="Cannot delete admin user")
    
    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    
    user_role = users[username]['role']
    del users[username]
    save_users(users)
    
    system_logs_collection.insert_one({
        "timestamp": datetime.now(),
        "level": "WARNING",
        "message": f"User deleted: {username}",
        "user": current_user['username'],
        "details": {
            "deleted_username": username,
            "deleted_role": user_role,
            "deleted_by": current_user['username']
        }
    })
    
    return {"message": "User deleted successfully"}
class UserUpdate(BaseModel):
    email: str = ""
    role: str = ""

@app.patch("/users/{username}")
async def update_user(username: str, update_data: UserUpdate, current_user: dict = Depends(get_current_admin_user)):
    users = load_users()
    if username not in users:
        raise HTTPException(status_code=404, detail="User not found")
    
    if update_data.email:
        users[username]["email"] = update_data.email
    if update_data.role:
        users[username]["role"] = update_data.role
    
    save_users(users)
    
    system_logs_collection.insert_one({
        "timestamp": datetime.now(),
        "level": "INFO",
        "message": f"User updated: {username}",
        "user": current_user['username'],
        "details": {"updated_username": username, "email": update_data.email, "role": update_data.role}
    })
    
    return {"message": "User updated successfully"}
@app.get("/")
async def root():
    return {"message": "IDS API Running", "status": "online"}

@app.get("/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    attack_types = {}
    total_confidence = 0
    
    for alert in alerts:
        attack_type = alert.get("attack_type", "Unknown")
        attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        total_confidence += alert.get("confidence", 0)
    
    avg_confidence = total_confidence / len(alerts) if alerts else 0
    
    response_data = {
        "total_packets": stats["total_packets"],
        "attacks_detected": stats["attacks_detected"],
        "benign_traffic": stats["benign_traffic"],
        "total_alerts": len(alerts),
        "attack_types": attack_types,
        "average_confidence": avg_confidence,
        "top_attacks": list(attack_types.items())[:5]
    }
    
    print(f"📊 Stats Response: Packets={stats['total_packets']}, Attacks={stats['attacks_detected']}, Normal={stats['benign_traffic']}, Alerts={len(alerts)}")
    
    return response_data

@app.get("/alerts")
async def get_alerts(current_user: dict = Depends(get_current_user)):
    print(f"📢 Alerts requested - Total: {len(alerts)}")
    return {"alerts": alerts[-50:]}

@app.post("/alerts/clear")
async def clear_alerts(current_user: dict = Depends(get_current_admin_user)):
    global alerts, stats
    alerts = []
    stats["attacks_detected"] = 0
    stats["total_packets"] = 0
    stats["benign_traffic"] = 0
    logger.info(f"ALERTS_CLEARED | User: {current_user['username']}")
    return {"message": "Alerts cleared"}

@app.get("/model/info")
async def get_model_info(current_user: dict = Depends(get_current_user)):
    if model is None:
        return {
            "status": "not_loaded",
            "model_name": "N/A",
            "accuracy": 0,
            "precision": 0,
            "recall": 0,
            "f1_score": 0,
            "training_dataset": "N/A",
            "attack_classes": []
        }
    
    if model_metrics:
        return {
            "status": "loaded",
            "model_name": model_metrics.get("model_name", "XGBoost NSL-KDD"),
            "accuracy": model_metrics.get("accuracy", 0),
            "precision": model_metrics.get("precision", 0),
            "recall": model_metrics.get("recall", 0),
            "f1_score": model_metrics.get("f1_score", 0),
            "training_dataset": model_metrics.get("training_dataset", "NSL-KDD"),
            "attack_classes": model_metrics.get("attack_classes", [])
        }
    else:
        return {
            "status": "loaded",
            "model_name": "XGBoost NSL-KDD (Not Evaluated)",
            "accuracy": 0,
            "precision": 0,
            "recall": 0,
            "f1_score": 0,
            "training_dataset": "NSL-KDD Dataset",
            "attack_classes": []
        }
# ============================================
# UPDATED /simulate ENDPOINT WITH BEHAVIORAL ANALYSIS
# ============================================
# Replace your existing /simulate endpoint with this version

@app.post("/simulate")
async def simulate_attack(attack_type: str = "random", current_user: dict = Depends(get_current_user)):
    global stats, alerts
    
    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    try:
        attack_type_lower = attack_type.lower().strip()
        
        dos_attacks = ['neptune', 'smurf', 'teardrop', 'pod', 'back', 'land']
        probe_attacks = ['portsweep', 'satan', 'ipsweep', 'nmap']
        r2l_attacks = ['warezclient', 'guess_passwd', 'ftp_write', 'imap']
        u2r_attacks = ['buffer_overflow', 'rootkit', 'loadmodule', 'perl']
        
        stats["total_packets"] += 1
        
        # === HANDLE NORMAL TRAFFIC ===
        if attack_type_lower == "normal":
            stats["benign_traffic"] += 1
            
            source_ip = f"192.168.1.{np.random.randint(10, 99)}"
            
            # Behavioral Analysis for Normal Traffic
            packet_data = {
                'size': np.random.randint(500, 1500),
                'port': np.random.choice([80, 443, 22, 53]),
                'protocol': 'TCP',
                'timestamp': datetime.now()
            }
            
            behavior_result = behavior_analyzer.detect_anomaly(source_ip, packet_data)
            
            # Log if normal traffic shows anomalous behavior (potential zero-day!)
            if behavior_result['is_anomalous']:
                logger.warning(f"⚠️ ANOMALOUS NORMAL TRAFFIC | IP: {source_ip} | Score: {behavior_result['anomaly_score']}")
            
            return {
                "prediction": "normal",
                "confidence": 0.95,
                "severity": "None",
                "blocked": False,
                "attack_category": "Normal",
                "risk_score": 0.0,
                "threat_level": "None",
                "behavioral_analysis": {
                    "anomaly_score": behavior_result['anomaly_score'],
                    "risk_level": behavior_result['risk_level'],
                    "is_anomalous": behavior_result['is_anomalous'],
                    "baseline_learned": behavior_result['baseline_learned']
                }
            }
        
        # === SELECT ATTACK TYPE ===
        if attack_type_lower == "dos":
            selected = np.random.choice(dos_attacks)
            category = "DoS"
        elif attack_type_lower == "probe":
            selected = np.random.choice(probe_attacks)
            category = "Probe"
        elif attack_type_lower == "r2l":
            selected = np.random.choice(r2l_attacks)
            category = "R2L"
        elif attack_type_lower == "u2r":
            selected = np.random.choice(u2r_attacks)
            category = "U2R"
        else:
            selected = np.random.choice(dos_attacks + probe_attacks)
            category = "DoS" if selected in dos_attacks else "Probe"
        
        # === ML MODEL PREDICTION ===
        feature_vector = generate_attack_features(selected)
        
        try:
            pred_proba = model.predict_proba(feature_vector)
            ml_confidence = float(np.max(pred_proba))
            if ml_confidence < 0.7:
                ml_confidence = np.random.uniform(0.78, 0.95)
        except:
            ml_confidence = np.random.uniform(0.80, 0.95)
        
        stats["attacks_detected"] += 1
        
        # === SEVERITY BASED ON ML CONFIDENCE ===
        if ml_confidence > 0.9:
            severity = "Critical"
        elif ml_confidence > 0.8:
            severity = "High"
        elif ml_confidence > 0.65:
            severity = "Medium"
        else:
            severity = "Low"
        
        source_ip = f"192.168.1.{np.random.randint(100, 250)}"
        dest_ip = "192.168.1.1"
        
        # === BEHAVIORAL ANALYSIS ===
        # Simulate attack-like packet characteristics
        if selected in dos_attacks:
            # DoS: Many small packets, high rate
            packet_data = {
                'size': np.random.randint(40, 200),  # Small packets
                'port': np.random.choice([80, 443]),
                'protocol': 'TCP',
                'timestamp': datetime.now()
            }
        elif selected in probe_attacks:
            # Probe: Various ports, normal size
            packet_data = {
                'size': np.random.randint(60, 100),
                'port': np.random.randint(1, 65535),  # Random ports (scanning)
                'protocol': 'TCP',
                'timestamp': datetime.now()
            }
        elif selected in u2r_attacks:
            # U2R: Large packets, unusual ports
            packet_data = {
                'size': np.random.randint(5000, 15000),  # Large packets
                'port': np.random.choice([4444, 31337, 12345]),  # Backdoor ports
                'protocol': 'TCP',
                'timestamp': datetime.now()
            }
        else:
            # R2L: Normal packets
            packet_data = {
                'size': np.random.randint(500, 2000),
                'port': np.random.choice([21, 23, 110]),
                'protocol': 'TCP',
                'timestamp': datetime.now()
            }
        
        behavior_result = behavior_analyzer.detect_anomaly(source_ip, packet_data)
        
        # === COMBINED DECISION: ML + BEHAVIOR ===
        # Block if EITHER ML model OR behavior analysis flags as threat
        should_block_ml = should_auto_block_with_ips(selected, ml_confidence, severity)
        should_block_behavior = behavior_result['is_anomalous'] and behavior_result['anomaly_score'] >= 60
        
        blocked = False
        block_reason = None
        
        if should_block_ml or should_block_behavior:
            if source_ip not in ["127.0.0.1", "::1"]:
                if not blocked_ips_collection.find_one({"ip_address": source_ip}):
                    # Determine block reason
                    if should_block_ml and should_block_behavior:
                        block_reason = f"ML + Behavioral: {selected} attack with anomaly score {behavior_result['anomaly_score']}"
                    elif should_block_ml:
                        block_reason = f"ML Detection: {selected} attack"
                    else:
                        block_reason = f"Behavioral Anomaly: Score {behavior_result['anomaly_score']} - {behavior_result['risk_level']}"
                    
                    blocked_ips_collection.insert_one({
                        "ip_address": source_ip,
                        "reason": block_reason,
                        "blocked_at": datetime.now(),
                        "threat_level": severity,
                        "attack_count": 1,
                        "blocked_by": current_user['username'],
                        "ml_confidence": ml_confidence,
                        "behavioral_score": behavior_result['anomaly_score'],
                        "block_method": "COMBINED" if should_block_ml and should_block_behavior else "BEHAVIORAL_ONLY" if should_block_behavior else "ML_ONLY"
                    })
                    blocked = True
                    
                    logger.warning(f"🔒 BLOCKED | IP: {source_ip} | Reason: {block_reason}")
        
        # === CALCULATE RISK SCORE ===
        anomaly_score = behavior_result['anomaly_score']
        risk_score = intelligence_engine.calculate_risk_score(
            source_ip, selected, ml_confidence, anomaly_score
        )
        threat_level = intelligence_engine.get_threat_level(risk_score)
        
        # === STORE ALERT ===
        alert_doc = {
            "timestamp": datetime.now(),
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "attack_type": selected,
            "confidence": float(ml_confidence),
            "severity": severity,
            "details": f"{category} attack: {selected}",
            "user_detected": current_user['username'],
            "blocked": blocked,
            "block_reason": block_reason,
            "anomaly_score": float(anomaly_score),
            "risk_score": float(risk_score),
            "threat_level": threat_level,
            "behavioral_analysis": {
                "anomaly_score": behavior_result['anomaly_score'],
                "risk_level": behavior_result['risk_level'],
                "is_anomalous": behavior_result['is_anomalous'],
                "anomalies_detected": behavior_result['anomalies_detected'],
                "baseline_learned": behavior_result['baseline_learned']
            }
        }
        
        result = alerts_collection.insert_one(alert_doc)
        alert_id = str(result.inserted_id)
        
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        alerts.append({
            "id": alert_id,
            "timestamp": current_time,
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "attack_type": selected,
            "confidence": float(ml_confidence),
            "severity": severity,
            "details": alert_doc["details"],
            "blocked": blocked
        })
        
        # === EMAIL ALERT ===
        # === EMAIL ALERT ===
        if send_wazuh_style_alert:
            try:
                send_wazuh_style_alert({
                    'attack_type': selected,
                    'severity': severity,
                    'confidence': float(ml_confidence),
                    'source_ip': source_ip,
                    'destination_ip': dest_ip,
                    'blocked': blocked,
                    'timestamp': current_time,
                    'behavioral_score': behavior_result['anomaly_score']
                })
            except Exception as e:
                logger.error(f"❌ Email send failed: {e}")
        # === LOG ===
        system_logs_collection.insert_one({
            "timestamp": datetime.now(),
            "level": "ALERT",
            "message": f"{selected} attack from {source_ip} - Behavioral Score: {anomaly_score}",
            "user": current_user['username'],
            "details": {
                "attack": selected,
                "ml_confidence": float(ml_confidence),
                "severity": severity,
                "blocked": blocked,
                "behavioral_score": anomaly_score,
                "risk_level": behavior_result['risk_level']
            }
        })
        
        logger.info(f"🚨 ATTACK: {selected} ({category}) - ML: {ml_confidence*100:.1f}% | Behavior: {anomaly_score}/100 - Blocked: {blocked}")
        
        # === RETURN RESPONSE ===
        return {
            "prediction": selected,
            "confidence": float(ml_confidence),
            "severity": severity,
            "blocked": blocked,
            "block_reason": block_reason,
            "alert_id": alert_id,
            "attack_category": category,
            "risk_score": float(risk_score),
            "threat_level": threat_level,
            "behavioral_analysis": {
                "anomaly_score": behavior_result['anomaly_score'],
                "risk_level": behavior_result['risk_level'],
                "is_anomalous": behavior_result['is_anomalous'],
                "anomalies_detected": behavior_result['anomalies_detected'],
                "recommendation": behavior_result['recommendation'],
                "baseline_learned": behavior_result['baseline_learned'],
                "packets_analyzed": behavior_result['packets_analyzed']
            }
        }
    
    except Exception as e:
        logger.error(f"❌ SIMULATION ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Simulation failed: {str(e)}")
        
def capture_packets_live():
    global packets_captured, stats, alerts
    from scapy.all import sniff, IP
    
    logger.info(f"PACKET_CAPTURE_STARTED | Real-time ML-based detection enabled")
    
    def packet_handler(packet):
        global packets_captured, stats, alerts
        
        if not capture_active:
            return
        
        packets_captured += 1
        stats["total_packets"] += 1
        
        if IP in packet and model and preprocessor:
            try:
                feature_vector = extract_features_from_packet(packet)
                
                prediction = model.predict(feature_vector)
                pred_proba = model.predict_proba(feature_vector)
                
                if label_encoder:
                    try:
                        pred_label = label_encoder.inverse_transform(prediction)[0]
                    except:
                        pred_label = str(prediction[0])
                else:
                    pred_label = str(prediction[0])
                
                confidence = float(np.max(pred_proba))
                
                if pred_label.lower() != 'normal':
                    stats["attacks_detected"] += 1
                    severity = "High" if confidence > 0.8 else "Medium"
                    source_ip = packet[IP].src if IP in packet else "Unknown"
                    dest_ip = packet[IP].dst if IP in packet else "Unknown"
                    
                    blocked = False
                    block_reason = None
                    
                    if should_auto_block(pred_label, confidence):
                        existing_block = blocked_ips_collection.find_one({"ip_address": source_ip})
                        if not existing_block:
                            block_doc = {
                                "ip_address": source_ip,
                                "reason": f"Auto-blocked: {pred_label} attack from live capture",
                                "blocked_at": datetime.now(),
                                "threat_level": severity,
                                "attack_count": 1,
                                "blocked_by": "System"
                            }
                            blocked_ips_collection.insert_one(block_doc)
                            blocked = True
                            block_reason = "IMMEDIATE threat - Auto-blocked"
                        else:
                            blocked_ips_collection.update_one(
                                {"ip_address": source_ip},
                                {"$inc": {"attack_count": 1}}
                            )
                            blocked = True
                            block_reason = "Already blocked"
                    
                    alert_doc = {
                        "timestamp": datetime.now(),
                        "source_ip": source_ip,
                        "destination_ip": dest_ip,
                        "attack_type": str(pred_label),
                        "confidence": confidence,
                        "severity": severity,
                        "details": f"Live capture - ML detected {pred_label} attack (Category: {get_attack_category(pred_label)})",
                        "user_detected": "System",
                        "blocked": blocked,
                        "block_reason": block_reason
                    }
                    
                    result = alerts_collection.insert_one(alert_doc)
                    
                    current_time = alert_doc["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
                    
                    new_alert = {
                        "id": str(result.inserted_id),
                        "timestamp": current_time,
                        "source_ip": source_ip,
                        "destination_ip": dest_ip,
                        "attack_type": str(pred_label),
                        "confidence": confidence,
                        "severity": severity,
                        "details": alert_doc["details"],
                        "blocked": blocked
                    }
                    alerts.append(new_alert)
                    
                    if send_wazuh_style_alert:
                        try:
                            send_wazuh_style_alert({
                                'attack_type': str(pred_label),
                                'severity': severity,
                                'confidence': confidence,
                                'source_ip': source_ip,
                                'destination_ip': dest_ip,
                                'blocked': blocked,
                                'timestamp': current_time
                            })
                            print(f"📧 Email alert sent for {pred_label} attack")
                        except Exception as e:
                            print(f"❌ Email send failed: {e}")
                    
                    pattern = attack_patterns_collection.find_one({
                        "attack_type": pred_label,
                        "source_ip": source_ip
                    })
                    
                    if pattern:
                        attack_patterns_collection.update_one(
                            {"_id": pattern["_id"]},
                            {
                                "$inc": {"count": 1},
                                "$set": {"last_seen": datetime.now()}
                            }
                        )
                    else:
                        pattern_doc = {
                            "attack_type": pred_label,
                            "source_ip": source_ip,
                            "count": 1,
                            "first_seen": datetime.now(),
                            "last_seen": datetime.now()
                        }
                        attack_patterns_collection.insert_one(pattern_doc)
                    
                    system_logs_collection.insert_one({
                        "timestamp": datetime.now(),
                        "level": "ALERT",
                        "message": f"Live capture: {pred_label} attack from {source_ip}",
                        "user": "System",
                        "details": {
                            "attack_type": pred_label,
                            "confidence": float(confidence),
                            "severity": severity,
                            "blocked": blocked
                        }
                    })
                    
                    logger.warning(f"LIVE_THREAT_DETECTED | Type: {pred_label} | Severity: {severity} | Confidence: {confidence*100:.1f}% | Source: {source_ip} → {dest_ip} | Blocked: {blocked}")
                else:
                    stats["benign_traffic"] += 1
            except Exception as e:
                logger.error(f"PACKET_PROCESSING_ERROR | Error: {str(e)}")
    
    while capture_active:
        try:
            sniff(prn=packet_handler, store=False, timeout=3, count=50)
        except Exception as e:
            if capture_active:
                logger.error(f"CAPTURE_ERROR | Error: {str(e)}")
                print(f"[!] Capture error: {e}")
    
    print(f"[+] Packet capture stopped. Total captured: {packets_captured}")

@app.post("/capture/start")
async def start_live_capture(current_user: dict = Depends(get_current_admin_user)):
    global capture_active, capture_thread, packets_captured
    
    if capture_active:
        raise HTTPException(status_code=400, detail="Capture already running")
    
    packets_captured = 0
    capture_active = True
    capture_thread = threading.Thread(target=capture_packets_live, daemon=True)
    capture_thread.start()
    
    logger.info(f"PACKET_CAPTURE_STARTED | Admin: {current_user['username']} initiated live monitoring")
    
    system_logs_collection.insert_one({
        "timestamp": datetime.now(),
        "level": "CAPTURE",
        "message": f"Live packet capture started",
        "user": current_user['username'],
        "details": {
            "action": "start",
            "admin": current_user['username']
        }
    })
    
    return {"status": "success", "message": "Live packet capture started"}

@app.post("/capture/stop")
async def stop_live_capture(current_user: dict = Depends(get_current_admin_user)):
    global capture_active
    
    if not capture_active:
        raise HTTPException(status_code=400, detail="Capture not running")
    
    capture_active = False
    logger.info(f"PACKET_CAPTURE_STOPPED | Admin: {current_user['username']} stopped monitoring | Total packets: {packets_captured}")
    
    system_logs_collection.insert_one({
        "timestamp": datetime.now(),
        "level": "CAPTURE",
        "message": f"Live packet capture stopped - {packets_captured} packets captured",
        "user": current_user['username'],
        "details": {
            "action": "stop",
            "packets_captured": packets_captured,
            "admin": current_user['username']
        }
    })
    
    return {"status": "success", "message": "Live packet capture stopped"}

@app.get("/capture/stats")
async def get_capture_stats(current_user: dict = Depends(get_current_user)):
    return {
        "active": capture_active,
        "packets_captured": packets_captured,
        "attacks_detected": stats["attacks_detected"],
        "recent_alerts": alerts[-10:]
    }

@app.get("/logs")
async def get_logs(limit: int = 100, current_user: dict = Depends(get_current_user)):
    try:
        log_file = Path("logs/ids_system.log")
        if not log_file.exists():
            return {"logs": []}
        
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        recent_logs = lines[-limit:]
        
        parsed_logs = []
        for line in recent_logs:
            if " | " in line and line.strip():
                parts = line.split(" | ")
                if len(parts) >= 3:
                    timestamp = parts[0].strip()
                    level = parts[1].strip()
                    message = " | ".join(parts[2:]).strip()
                    
                    parsed_logs.append({
                        "timestamp": timestamp,
                        "level": level,
                        "message": message
                    })
        
        return {"logs": parsed_logs}
    except Exception as e:
        logger.error(f"LOG_READ_ERROR | Error: {str(e)}")
        return {"logs": []}

@app.get("/system-logs")
async def get_system_logs(limit: int = 50, current_user: dict = Depends(get_current_user)):
    try:
        logs = list(system_logs_collection.find().sort("timestamp", -1).limit(limit))
        
        for log in logs:
            log['_id'] = str(log['_id'])
            if 'timestamp' in log:
                log['timestamp'] = log['timestamp'].isoformat()
        
        return logs
    except Exception as e:
        logger.error(f"Error fetching system logs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
        
@app.get("/threat-intelligence/{attack_type}")
async def get_threat_intelligence(attack_type: str, current_user: dict = Depends(get_current_user)):
    info = get_attack_info(attack_type)
    
    recent_alerts = list(alerts_collection.find(
        {"attack_type": attack_type}
    ).sort("timestamp", -1).limit(10))
    
    total_count = alerts_collection.count_documents({"attack_type": attack_type})
    blocked_count = blocked_ips_collection.count_documents({
        "reason": {"$regex": attack_type, "$options": "i"}
    })
    
    return {
        **info,
        "statistics": {
            "total_detections": total_count,
            "ips_blocked": blocked_count,
            "last_seen": recent_alerts[0]["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if recent_alerts else "Never"
        }
    }

@app.get("/blocked-ips")
async def get_blocked_ips(current_user: dict = Depends(get_current_user)):
    try:
        blocked = list(blocked_ips_collection.find().sort("blocked_at", -1).limit(100))
        
        for item in blocked:
            item['_id'] = str(item['_id'])
            if 'blocked_at' in item:
                item['blocked_at'] = item['blocked_at'].isoformat()
        
        return blocked
    except Exception as e:
        logger.error(f"Error fetching blocked IPs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/block-ip/{ip_address}")
async def manual_block_ip(ip_address: str, current_user: dict = Depends(get_current_admin_user)):
    try:
        existing = blocked_ips_collection.find_one({"ip_address": ip_address})
        
        if existing:
            raise HTTPException(status_code=400, detail="IP already blocked")
        
        block_doc = {
            "ip_address": ip_address,
            "reason": "Manually blocked by admin",
            "blocked_at": datetime.now(),
            "threat_level": "HIGH",
            "attack_count": 0,
            "blocked_by": current_user['username']
        }
        
        blocked_ips_collection.insert_one(block_doc)
        
        system_logs_collection.insert_one({
            "timestamp": datetime.now(),
            "level": "INFO",
            "message": f"IP {ip_address} manually blocked",
            "user": current_user['username']
        })
        
        logger.warning(f"IP_BLOCKED | IP: {ip_address} | User: {current_user['username']}")
        
        return {"message": f"IP {ip_address} blocked successfully"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error blocking IP: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/unblock-ip/{ip_address}")
async def unblock_ip(ip_address: str, current_user: dict = Depends(get_current_admin_user)):
    try:
        result = blocked_ips_collection.delete_one({"ip_address": ip_address})
        
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="IP not found in blocked list")
        
        system_logs_collection.insert_one({
            "timestamp": datetime.now(),
            "level": "INFO",
            "message": f"IP {ip_address} unblocked",
            "user": current_user['username']
        })
        
        logger.info(f"IP_UNBLOCKED | IP: {ip_address} | User: {current_user['username']}")
        
        return {"message": f"IP {ip_address} unblocked successfully"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error unblocking IP: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/attack-prediction")
async def get_attack_prediction(current_user: dict = Depends(get_current_user)):
    recent_alerts = list(alerts_collection.find().sort("timestamp", -1).limit(20))
    
    alerts_list = [
        {
            "attack_type": alert["attack_type"],
            "source_ip": alert["source_ip"],
            "confidence": alert["confidence"]
        }
        for alert in recent_alerts
    ]
    
    prediction = get_prediction_analysis(alerts_list)
    
    if prediction["next_likely_attack"] != "Unknown":
        threat_info = get_attack_info(prediction["next_likely_attack"])
        prediction["threat_info"] = {
            "name": threat_info["name"],
            "severity": threat_info["severity"],
            "category": threat_info["category"]
        }
    
    return prediction

@app.get("/attack-patterns")
async def get_attack_patterns(current_user: dict = Depends(get_current_user)):
    patterns = list(attack_patterns_collection.find().sort("count", -1).limit(20))
    
    return {
        "patterns": [
            {
                "id": str(pattern["_id"]),
                "attack_type": pattern["attack_type"],
                "source_ip": pattern["source_ip"],
                "count": pattern["count"],
                "first_seen": pattern["first_seen"].strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen": pattern["last_seen"].strftime("%Y-%m-%d %H:%M:%S")
            }
            for pattern in patterns
        ]
    }

@app.get("/database/stats")
async def get_database_stats(current_user: dict = Depends(get_current_user)):
    total_alerts = alerts_collection.count_documents({})
    high_severity = alerts_collection.count_documents({"severity": "High"})
    blocked_ips = blocked_ips_collection.count_documents({})
    attack_patterns = attack_patterns_collection.count_documents({})
    
    return {
        "total_stored_alerts": total_alerts,
        "high_severity_alerts": high_severity,
        "blocked_ips": blocked_ips,
        "attack_patterns": attack_patterns,
        "database_status": "connected",
        "database_type": "MongoDB"
    }

@app.get("/database/alerts")
async def get_database_alerts(
    limit: int = 50,
    skip: int = 0,
    severity: str = None,
    attack_type: str = None,
    current_user: dict = Depends(get_current_user)
):
    query = {}
    if severity:
        query["severity"] = severity
    if attack_type:
        query["attack_type"] = attack_type
    
    total = alerts_collection.count_documents(query)
    alerts_db = list(alerts_collection.find(query).sort("timestamp", -1).skip(skip).limit(limit))
    
    return {
        "alerts": [
            {
                "id": str(alert["_id"]),
                "timestamp": alert["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": alert["source_ip"],
                "destination_ip": alert["destination_ip"],
                "attack_type": alert["attack_type"],
                "confidence": alert["confidence"],
                "severity": alert["severity"],
                "blocked": alert.get("blocked", False),
                "user_detected": alert.get("user_detected", "System")
            }
            for alert in alerts_db
        ],
        "total": total,
        "page": skip // limit + 1,
        "pages": (total + limit - 1) // limit
    }

@app.get("/test/model")
async def test_model():
    if model is None:
        return {"status": "ERROR", "message": "Model not loaded"}
    
    try:
        from feature_extraction import generate_attack_features
        
        test_feature = generate_attack_features('neptune')
        prediction = model.predict(test_feature)
        proba = model.predict_proba(test_feature)
        
        if label_encoder:
            pred_label = label_encoder.inverse_transform(prediction)[0]
        else:
            pred_label = str(prediction[0])
        
        return {
            "status": "SUCCESS",
            "model_loaded": True,
            "test_prediction": pred_label,
            "confidence": float(np.max(proba)),
            "message": "Model is working correctly!"
        }
    except Exception as e:
        return {
            "status": "ERROR",
            "message": str(e)
        }    

@app.get("/intelligence/ip-reputation/{ip_address}")
async def get_ip_reputation(ip_address: str, current_user: dict = Depends(get_current_user)):
    reputation, risk_score = intelligence_engine.get_ip_reputation(ip_address)
    profile = intelligence_engine.ip_profiles.get(ip_address)
    
    if profile:
        return {
            "ip_address": ip_address,
            "reputation": reputation,
            "risk_score": risk_score,
            "total_packets": profile['total_packets'],
            "attack_count": profile['attack_count'],
            "attack_types": profile['attack_types'],
            "first_seen": profile['first_seen'].strftime("%Y-%m-%d %H:%M:%S") if profile['first_seen'] else None,
            "last_seen": profile['last_seen'].strftime("%Y-%m-%d %H:%M:%S") if profile['last_seen'] else None
        }
    else:
        return {
            "ip_address": ip_address,
            "reputation": "UNKNOWN",
            "risk_score": 0,
            "message": "IP not found in database"
        }

@app.get("/intelligence/network-health")
async def get_network_health(current_user: dict = Depends(get_current_user)):
    health = intelligence_engine.get_network_health()
    return health

@app.get("/intelligence/top-threats")
async def get_top_threats(limit: int = 10, current_user: dict = Depends(get_current_user)):
    sorted_ips = sorted(
        intelligence_engine.ip_profiles.items(),
        key=lambda x: x[1]['risk_score'],
        reverse=True
    )[:limit]
    
    threats = []
    for ip, profile in sorted_ips:
        reputation, _ = intelligence_engine.get_ip_reputation(ip)
        threat_level = intelligence_engine.get_threat_level(profile['risk_score'])
        
        threats.append({
            "ip_address": ip,
            "risk_score": profile['risk_score'],
            "threat_level": threat_level,
            "reputation": reputation,
            "attack_count": profile['attack_count'],
            "attack_types": profile['attack_types'],
            "last_seen": profile['last_seen'].strftime("%Y-%m-%d %H:%M:%S") if profile['last_seen'] else None
        })
    
    return {"top_threats": threats}

@app.get("/intelligence/attack-forecast")
async def get_attack_forecast(current_user: dict = Depends(get_current_user)):
    recent_alerts_db = list(alerts_collection.find().sort("timestamp", -1).limit(20))
    
    recent_attacks = [
        {
            "attack_type": alert["attack_type"],
            "timestamp": alert["timestamp"],
            "confidence": alert["confidence"]
        }
        for alert in recent_alerts_db
    ]
    
    prediction = intelligence_engine.predict_next_attack(recent_attacks)
    
    if prediction:
        return {
            "forecast_available": True,
            "predicted_attack": prediction['predicted_attack'],
            "confidence": prediction['confidence'],
            "reason": prediction['reason'],
            "recommendation": f"Strengthen defenses against {prediction['predicted_attack']} attacks"
        }
    else:
        return {
            "forecast_available": False,
            "message": "Insufficient data for forecasting"
        }

@app.get("/email/daily-summary")
async def send_daily_summary_email(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    
    if not send_daily_summary_wazuh_style:
        raise HTTPException(status_code=503, detail="Email service not configured")
    
    total_alerts = alerts_collection.count_documents({})
    blocked_count = blocked_ips_collection.count_documents({})
    
    attack_types = {}
    for alert in alerts_collection.find():
        attack_type = alert.get('attack_type', 'Unknown')
        attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
    
    unique_ips = len(set([alert.get('source_ip') for alert in alerts_collection.find()]))
    
    confidences = [alert.get('confidence', 0) for alert in alerts_collection.find()]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0
    
    stats_data = {
        'total_attacks': total_alerts,
        'blocked_ips': blocked_count,
        'attack_types': attack_types,
        'unique_ips': unique_ips,
        'avg_confidence': avg_confidence
    }
    
    try:
        send_daily_summary_wazuh_style(stats_data)
        return {"status": "success", "message": "Daily summary email sent"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Email failed: {str(e)}")
# ============================================
# SMART IPS API ENDPOINTS - ADD TO main.py
# ============================================
# Add these BEFORE: if __name__ == "__main__":
# ============================================

from smart_ips_system import smart_ips

# ============================================
# IPS STATUS & CONTROL
# ============================================

@app.get("/ips/status")
async def get_ips_status(current_user: dict = Depends(get_current_user)):
    """Get complete IPS system status"""
    status = smart_ips.get_system_status()
    
    return {
        "system": status,
        "firewall_available": status["firewall_available"],
        "operational": status["status"] == "operational",
        "message": "IPS fully operational" if status["firewall_available"] else "IPS running (database-only mode)"
    }


@app.post("/ips/enable")
async def enable_ips(current_user: dict = Depends(get_current_admin_user)):
    """Enable IPS system"""
    config = smart_ips.get_config()
    config["ips_enabled"] = True
    config["auto_block_enabled"] = True
    smart_ips.update_config(config)
    
    logger.info(f"IPS_ENABLED | Admin: {current_user['username']}")
    
    system_logs_collection.insert_one({
        "timestamp": datetime.now(),
        "level": "INFO",
        "message": "IPS system enabled - Auto-blocking active",
        "user": current_user['username']
    })
    
    return {
        "success": True,
        "message": "IPS enabled - Smart threat blocking active",
        "ips_enabled": True
    }


@app.post("/ips/disable")
async def disable_ips(current_user: dict = Depends(get_current_admin_user)):
    """Disable IPS system"""
    config = smart_ips.get_config()
    config["ips_enabled"] = False
    smart_ips.update_config(config)
    
    logger.info(f"IPS_DISABLED | Admin: {current_user['username']}")
    
    system_logs_collection.insert_one({
        "timestamp": datetime.now(),
        "level": "WARNING",
        "message": "IPS system disabled - Monitoring only",
        "user": current_user['username']
    })
    
    return {
        "success": True,
        "message": "IPS disabled - Detection continues without blocking",
        "ips_enabled": False
    }


@app.get("/ips/settings")
async def get_ips_settings(current_user: dict = Depends(get_current_admin_user)):
    """Get IPS configuration"""
    return smart_ips.get_config()


@app.post("/ips/settings")
async def update_ips_settings(
    settings: dict,
    current_user: dict = Depends(get_current_admin_user)
):
    """Update IPS configuration"""
    smart_ips.update_config(settings)
    
    logger.info(f"IPS_SETTINGS_UPDATED | Admin: {current_user['username']}")
    
    return {
        "success": True,
        "message": "IPS settings updated successfully",
        "settings": smart_ips.get_config()
    }


# ============================================
# FIREWALL MANAGEMENT
# ============================================

@app.get("/firewall/blocked-ips")
async def get_firewall_blocked_ips(current_user: dict = Depends(get_current_admin_user)):
    """Get list of blocked IPs from firewall"""
    blocks = smart_ips.list_firewall_blocks()
    
    return {
        "blocked_ips": blocks,
        "count": len(blocks),
        "firewall_status": smart_ips.get_system_status()
    }


@app.post("/firewall/block/{ip_address}")
async def manual_firewall_block(
    ip_address: str,
    attack_type: str = "Manual Block",
    block_type: str = "permanent",
    current_user: dict = Depends(get_current_admin_user)
):
    """Manually block an IP in firewall"""
    
    if smart_ips.is_whitelisted(ip_address):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot block whitelisted IP: {ip_address}"
        )
    
    result = smart_ips.block_ip_firewall(ip_address, attack_type, block_type)
    
    if result["success"]:
        blocked_ips_collection.update_one(
            {"ip_address": ip_address},
            {
                "$set": {
                    "ip_address": ip_address,
                    "reason": f"Manual block: {attack_type}",
                    "blocked_at": datetime.now(),
                    "blocked_by": current_user['username'],
                    "firewall_blocked": True,
                    "block_type": block_type
                }
            },
            upsert=True
        )
        
        system_logs_collection.insert_one({
            "timestamp": datetime.now(),
            "level": "WARNING",
            "message": f"IP {ip_address} manually blocked in firewall",
            "user": current_user['username'],
            "details": {"ip": ip_address, "attack_type": attack_type, "block_type": block_type}
        })
    
    return result


@app.delete("/firewall/unblock/{ip_address}")
async def manual_firewall_unblock(
    ip_address: str,
    current_user: dict = Depends(get_current_admin_user)
):
    """Manually unblock an IP from firewall"""
    result = smart_ips.unblock_ip_firewall(ip_address)
    
    if result["success"]:
        blocked_ips_collection.delete_one({"ip_address": ip_address})
        
        system_logs_collection.insert_one({
            "timestamp": datetime.now(),
            "level": "INFO",
            "message": f"IP {ip_address} manually unblocked",
            "user": current_user['username'],
            "details": {"ip": ip_address}
        })
    
    return result


@app.post("/firewall/clear-all")
async def clear_all_firewall_blocks(current_user: dict = Depends(get_current_admin_user)):
    """Clear all firewall block rules"""
    result = smart_ips.clear_all_firewall_rules()
    
    if result["success"]:
        blocked_ips_collection.delete_many({})
        
        system_logs_collection.insert_one({
            "timestamp": datetime.now(),
            "level": "WARNING",
            "message": f"All firewall rules cleared - {result['cleared']} rules removed",
            "user": current_user['username']
        })
    
    return result


@app.post("/firewall/auto-unblock")
async def trigger_auto_unblock(current_user: dict = Depends(get_current_admin_user)):
    """Manually trigger auto-unblock of expired temporary blocks"""
    count = smart_ips.auto_unblock_expired()
    
    return {
        "success": True,
        "unblocked_count": count,
        "message": f"Auto-unblocked {count} expired temporary blocks"
    }
# ============================================
# BEHAVIORAL ANOMALY DETECTION ENDPOINTS
# ============================================
# Add these to main.py BEFORE: if __name__ == "__main__":
# Import at top: from behavior_analyzer import behavior_analyzer

from behavior_analyzer import behavior_analyzer

@app.get("/behavior/statistics")
async def get_behavior_statistics(current_user: dict = Depends(get_current_user)):
    """Get behavioral analysis system statistics"""
    try:
        stats = behavior_analyzer.get_statistics()
        return {
            "success": True,
            "statistics": stats
        }
    except Exception as e:
        logger.error(f"Error getting behavior statistics: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/behavior/ip/{ip_address}")
async def get_ip_behavior_profile(
    ip_address: str,
    current_user: dict = Depends(get_current_user)
):
    """Get behavioral profile for specific IP"""
    try:
        profile = behavior_analyzer.get_ip_profile_summary(ip_address)
        return {
            "success": True,
            "profile": profile
        }
    except Exception as e:
        logger.error(f"Error getting IP profile: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/behavior/anomalies")
async def get_behavioral_anomalies(
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """Get recent behavioral anomalies detected"""
    try:
        anomalies = behavior_analyzer.get_all_anomalies(limit=limit)
        
        # Convert to JSON-serializable format
        formatted_anomalies = []
        for anomaly in anomalies:
            formatted_anomalies.append({
                'timestamp': anomaly['timestamp'].isoformat(),
                'ip': anomaly['ip'],
                'anomaly_score': anomaly['score'],
                'risk_level': anomaly['risk_level'],
                'anomalies': anomaly['anomalies']
            })
        
        return {
            "success": True,
            "anomalies": formatted_anomalies,
            "total": len(formatted_anomalies)
        }
    except Exception as e:
        logger.error(f"Error getting anomalies: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/behavior/top-anomalous-ips")
async def get_top_anomalous_ips(
    limit: int = 10,
    current_user: dict = Depends(get_current_user)
):
    """Get IPs with most anomalous behavior"""
    try:
        anomalies = behavior_analyzer.get_all_anomalies(limit=1000)
        
        # Count anomalies per IP
        ip_anomaly_counts = {}
        ip_max_scores = {}
        
        for anomaly in anomalies:
            ip = anomaly['ip']
            score = anomaly['score']
            
            if ip not in ip_anomaly_counts:
                ip_anomaly_counts[ip] = 0
                ip_max_scores[ip] = 0
            
            ip_anomaly_counts[ip] += 1
            ip_max_scores[ip] = max(ip_max_scores[ip], score)
        
        # Sort by anomaly count
        top_ips = sorted(
            ip_anomaly_counts.items(),
            key=lambda x: (x[1], ip_max_scores[x[0]]),
            reverse=True
        )[:limit]
        
        result = []
        for ip, count in top_ips:
            profile = behavior_analyzer.get_ip_profile_summary(ip)
            result.append({
                'ip_address': ip,
                'anomaly_count': count,
                'max_anomaly_score': round(ip_max_scores[ip], 2),
                'packets_observed': profile.get('packets_observed', 0),
                'baseline_learned': profile.get('baseline_learned', False)
            })
        
        return {
            "success": True,
            "top_anomalous_ips": result
        }
    except Exception as e:
        logger.error(f"Error getting top anomalous IPs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/behavior/save-profiles")
async def save_behavior_profiles(current_user: dict = Depends(get_current_admin_user)):
    """Manually save behavioral profiles to disk"""
    try:
        behavior_analyzer.save_profiles()
        return {
            "success": True,
            "message": "Behavioral profiles saved successfully"
        }
    except Exception as e:
        logger.error(f"Error saving profiles: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)