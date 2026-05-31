from pymongo import MongoClient
from datetime import datetime
import os

MONGO_URL = os.getenv("MONGODB_URI", os.getenv("MONGO_URL", "mongodb://localhost:27017/"))
DATABASE_NAME = os.getenv("DATABASE_NAME", "ids_database")

client = MongoClient(MONGO_URL)
db = client[DATABASE_NAME]

alerts_collection = db["alerts"]
blocked_ips_collection = db["blocked_ips"]
attack_patterns_collection = db["attack_patterns"]
users_collection = db["users"]
system_logs_collection = db["system_logs"]

try:
    alerts_collection.create_index("timestamp")
    alerts_collection.create_index("source_ip")
    alerts_collection.create_index("attack_type")
    blocked_ips_collection.create_index("ip_address", unique=True)
    attack_patterns_collection.create_index([("attack_type", 1), ("source_ip", 1)])
    print("[+] MongoDB connected successfully")
    print(f"[+] Database: {DATABASE_NAME}")
    print(f"[+] Collections: alerts, blocked_ips, attack_patterns, system_logs")
except Exception as e:
    print(f"[!] MongoDB index creation skipped: {e}")

def get_db():
    return db

def close_db():
    client.close()
