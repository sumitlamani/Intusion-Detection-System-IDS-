import os, time, json, urllib.request, urllib.error
import argparse

# macOS fix: Prevent Objective-C runtime from crashing during subprocess forks (used by scapy/urllib)
os.environ["OBJC_DISABLE_INITIALIZE_FORK_SAFETY"] = "YES"
from ids_engine import engine, CONFIG

# Parse arguments for API Key and Server URL
parser = argparse.ArgumentParser(description="IDS Sentinel Agent")
parser.add_argument("--api-key", required=True, help="Agent API Key from the Central Dashboard")
parser.add_argument("--server", default="http://localhost:8080", help="URL of the Central Dashboard (default: http://localhost:8080)")
parser.add_argument("--interface", help="Network interface to sniff (e.g., en0, eth0)")
args = parser.parse_args()

if args.interface:
    engine.config["INTERFACE"] = args.interface

print(f"[*] Starting IDS Agent...")
print(f"[*] Server URL: {args.server}")
print(f"[*] API Key: {args.api_key[:5]}...{args.api_key[-4:]}")

engine.start()

def sync_with_server():
    last_alert_index = 0
    while True:
        try:
            # Get current stats
            stats = engine.get_stats()
            
            # Get new alerts since last sync
            new_alerts = []
            current_total = len(engine.alerts)
            if current_total > last_alert_index:
                for i in range(last_alert_index, current_total):
                    new_alerts.append(engine.alerts[i])
                last_alert_index = current_total
                
            # Prepare payload
            payload = {
                "stats": stats,
                "alerts": new_alerts
            }
            
            # Send to server
            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(f"{args.server}/api/agent/sync", data=data, 
                                         headers={"Content-Type": "application/json", "X-API-Key": args.api_key})
            
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    resp = json.loads(r.read().decode())
                    if resp.get("status") == "ok":
                        pass
            except urllib.error.HTTPError as e:
                print(f"[!] Sync failed: HTTP {e.code}")
            except Exception as e:
                print(f"[!] Sync error: {e}")
                
        except Exception as e:
            print(f"[!] Agent error: {e}")
            
        time.sleep(2)

# Run sync loop
try:
    sync_with_server()
except KeyboardInterrupt:
    print("\n[*] Shutting down Agent...")
