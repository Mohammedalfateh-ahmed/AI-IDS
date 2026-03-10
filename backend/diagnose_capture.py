import sys
import os

print("=" * 70)
print("AI-IDS PACKET CAPTURE DIAGNOSTIC")
print("=" * 70)
print()

print("[1/6] Checking Python version...")
print(f"Python: {sys.version}")
print()

print("[2/6] Checking Scapy installation...")
try:
    import scapy
    print(f"✓ Scapy version: {scapy.__version__}")
except ImportError as e:
    print(f"✗ Scapy not installed: {e}")
    print("Run: pip install scapy")
    sys.exit(1)
print()

print("[3/6] Checking Npcap installation...")
npcap_paths = [
    "C:\\Windows\\System32\\Npcap",
    "C:\\Program Files\\Npcap",
]
npcap_found = False
for path in npcap_paths:
    if os.path.exists(path):
        print(f"✓ Npcap found at: {path}")
        npcap_found = True
        break
if not npcap_found:
    print("✗ Npcap NOT found!")
    print("Download and install from: https://npcap.com/")
    print("This is REQUIRED for packet capture on Windows!")
print()

print("[4/6] Checking network interfaces...")
try:
    from scapy.all import get_if_list, conf
    interfaces = get_if_list()
    print(f"✓ Found {len(interfaces)} interfaces:")
    for i, iface in enumerate(interfaces):
        marker = " ← DEFAULT" if iface == conf.iface else ""
        wifi_marker = " ← WIFI?" if any(k in iface.lower() for k in ['wi-fi', 'wlan', 'wireless', 'wifi']) else ""
        print(f"  {i}. {iface}{marker}{wifi_marker}")
except Exception as e:
    print(f"✗ Error: {e}")
print()

print("[5/6] Checking netifaces...")
try:
    import netifaces
    print("✓ Netifaces installed")
    interfaces = []
    for iface in netifaces.interfaces():
        try:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0]['addr']
                interfaces.append({'name': iface, 'ip': ip})
                wifi_marker = " ← WIFI?" if any(k in iface.lower() for k in ['wi-fi', 'wlan', 'wireless', 'wifi']) else ""
                print(f"  {iface}: {ip}{wifi_marker}")
        except:
            pass
except ImportError:
    print("✗ Netifaces not installed")
    print("Run: pip install netifaces")
print()

print("[6/6] Testing packet capture (10 seconds)...")
print("Attempting to capture 5 packets (timeout 10s)...")
print("Please wait...")
try:
    from scapy.all import sniff
    
    def packet_callback(pkt):
        print(f"  ✓ Captured packet: {pkt.summary()}")
    
    packets = sniff(count=5, timeout=10, prn=packet_callback)
    
    if len(packets) > 0:
        print(f"✓ Successfully captured {len(packets)} packets!")
        print("Packet capture is WORKING!")
    else:
        print("✗ No packets captured in 10 seconds")
        print("Possible issues:")
        print("  - Not running as Administrator")
        print("  - Npcap not installed")
        print("  - Firewall/Antivirus blocking")
        print("  - No network activity")
        
except PermissionError:
    print("✗ PERMISSION DENIED!")
    print("You MUST run this as Administrator!")
    print("Right-click PowerShell → Run as Administrator")
    
except Exception as e:
    print(f"✗ Error: {e}")
    print("Npcap may not be installed or configured correctly")

print()
print("=" * 70)
print("DIAGNOSTIC COMPLETE")
print("=" * 70)