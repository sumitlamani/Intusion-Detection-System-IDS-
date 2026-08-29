from flask import Flask, jsonify, render_template, Response, request, stream_with_context, session, redirect, url_for, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import os
os.environ["OBJC_DISABLE_INITIALIZE_FORK_SAFETY"] = "YES"
from ids_engine import CONFIG
import json, time, urllib.request, urllib.error
import sqlite3, secrets, threading, requests
from functools import wraps
from rag_engine import RAGEngine
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per minute"],
    storage_uri="memory://",
)

def get_secret_key():
    secret_path = os.path.join(os.path.dirname(__file__), ".flask_secret")
    if os.path.exists(secret_path):
        with open(secret_path, "r") as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(secret_path, "w") as f:
        f.write(key)
    return key

app.secret_key = get_secret_key()

DB_PATH = os.path.join(os.path.dirname(__file__), "ids_data.db")
rag_engine = RAGEngine(DB_PATH)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'viewer',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY, timestamp TEXT, alert_type TEXT,
            severity TEXT, source_ip TEXT, dest_ip TEXT,
            description TEXT, packet_count INTEGER, details TEXT
        );
        
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            last_seen TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS agent_stats (
            agent_id TEXT PRIMARY KEY,
            stats_json TEXT,
            alerts_triggered INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS config_store (key TEXT PRIMARY KEY, value TEXT);
    """)
    try:
        conn.execute("ALTER TABLE alerts ADD COLUMN agent_id TEXT DEFAULT 'local'")
    except sqlite3.OperationalError:
        pass
    cur = conn.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        pw = generate_password_hash("admin123")
        conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", ("admin", pw, "admin"))
        conn.commit()
        print("[IDS] Default login: admin / admin123")
    conn.close()

init_db()



def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            if request.path.startswith("/api/"): return jsonify({"error":"unauthorized"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin": return jsonify({"error":"admin only"}), 403
        return f(*args, **kwargs)
    return decorated

vt_request_times = []
VT_CACHE = {}

def can_vt_request():
    global vt_request_times
    now = time.time()
    vt_request_times = [t for t in vt_request_times if now-t < 60]
    return len(vt_request_times) < 4

def record_vt_request(): vt_request_times.append(time.time())



def load_config_from_db():
    try:
        conn = get_db()
        rows = conn.execute("SELECT key, value FROM config_store").fetchall()
        conn.close()
        for row in rows:
            CONFIG[row["key"]] = json.loads(row["value"])
            if row["key"] == "GEMINI_API_KEY":
                rag_engine.configure(CONFIG["GEMINI_API_KEY"])
    except: pass

load_config_from_db()



@app.route("/login", methods=["GET"])
def login_page():
    if session.get("user"): return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login_post():
    data = request.get_json() or {}
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (data.get("username","").strip(),)).fetchone()
    conn.close()
    if user and check_password_hash(user["password_hash"], data.get("password","")):
        session["user"] = user["username"]; session["role"] = user["role"]
        return jsonify({"status":"ok","role":user["role"]})
    return jsonify({"status":"error","message":"Invalid credentials"}), 401

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login_page"))

@app.route("/")
@login_required
def index():
    return render_template("index.html", username=session.get("user"), role=session.get("role"))

@app.route("/api/alerts")
@login_required
def get_alerts():
    agent_id = request.args.get("agent_id")
    limit = int(request.args.get("limit", 50))
    if not agent_id: return jsonify({"alerts": [], "total": 0})
    
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM alerts WHERE agent_id=? ORDER BY timestamp DESC LIMIT ?", (agent_id, limit)).fetchall()
    except Exception:
        rows = []
    conn.close()
    
    alerts = []
    for r in rows:
        d = dict(r)
        d["details"] = json.loads(d.get("details") or "{}")
        alerts.append(d)
        
    return jsonify({"alerts": alerts, "total": len(alerts)})

@app.route("/api/alerts/export")
@login_required
def export_alerts():
    conn = get_db()
    rows = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 1000").fetchall()
    conn.close()
    lines = ["id,timestamp,alert_type,severity,source_ip,dest_ip,description,packet_count"]
    for r in rows:
        lines.append(f'{r["id"]},{r["timestamp"]},{r["alert_type"]},{r["severity"]},{r["source_ip"]},{r["dest_ip"]},"{r["description"]}",{r["packet_count"]}')
    return Response("\n".join(lines), mimetype="text/csv",
                    headers={"Content-Disposition":"attachment;filename=ids_alerts.csv"})



@app.route("/api/alerts/clear", methods=["POST"])
@login_required
@admin_required
def clear_alerts():
    agent_id = request.args.get("agent_id")
    if agent_id:
        conn = get_db()
        conn.execute("DELETE FROM alerts WHERE agent_id=?", (agent_id,))
        conn.commit(); conn.close()
    return jsonify({"status":"ok"})

@app.route("/api/users", methods=["GET"])
@login_required
@admin_required
def list_users():
    conn = get_db()
    users = conn.execute("SELECT id,username,role,created_at FROM users").fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route("/api/users", methods=["POST"])
@login_required
@admin_required
def create_user():
    data = request.get_json()
    try:
        conn = get_db()
        conn.execute("INSERT INTO users (username,password_hash,role) VALUES (?,?,?)",
                     (data.get("username","").strip(), generate_password_hash(data.get("password","")), data.get("role","viewer")))
        conn.commit(); conn.close()
        return jsonify({"status":"ok"})
    except sqlite3.IntegrityError:
        return jsonify({"error":"username already exists"}), 409

@app.route("/api/users/<int:uid>", methods=["DELETE"])
@login_required
@admin_required
def delete_user(uid):
    conn = get_db(); conn.execute("DELETE FROM users WHERE id=?", (uid,)); conn.commit(); conn.close()
    return jsonify({"status":"ok"})

@app.route("/api/change-password", methods=["POST"])
@login_required
def change_password():
    data = request.get_json()
    new_pw = data.get("new_password","")
    if len(new_pw) < 6: return jsonify({"error":"Min 6 characters"}), 400
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (session["user"],)).fetchone()
    if not user or not check_password_hash(user["password_hash"], data.get("old_password","")):
        conn.close(); return jsonify({"error":"Current password wrong"}), 401
    conn.execute("UPDATE users SET password_hash=? WHERE username=?", (generate_password_hash(new_pw), session["user"]))
    conn.commit(); conn.close()
    return jsonify({"status":"ok"})


@app.route("/api/agents", methods=["POST"])
@login_required
@admin_required
def create_agent():
    data = request.get_json() or {}
    name = data.get("name", "Unnamed Agent").strip()
    agent_id = secrets.token_hex(8)
    api_key = "ak_" + secrets.token_hex(16)
    conn = get_db()
    conn.execute("INSERT INTO agents (id, name, api_key) VALUES (?, ?, ?)", (agent_id, name, api_key))
    conn.execute("INSERT INTO agent_stats (agent_id, stats_json) VALUES (?, ?)", (agent_id, "{}"))
    conn.commit(); conn.close()
    return jsonify({"id": agent_id, "name": name, "api_key": api_key})

@app.route("/api/agents", methods=["GET"])
@login_required
def get_agents():
    conn = get_db()
    rows = conn.execute("SELECT id, name, last_seen, created_at FROM agents ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/agents/<agent_id>", methods=["DELETE"])
@login_required
@admin_required
def delete_agent(agent_id):
    conn = get_db()
    conn.execute("DELETE FROM agents WHERE id = ?", (agent_id,))
    conn.execute("DELETE FROM agent_stats WHERE agent_id = ?", (agent_id,))
    conn.execute("DELETE FROM alerts WHERE agent_id = ?", (agent_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

@app.route("/api/agent/download")
@limiter.exempt
def download_agent():
    # Serve the agent.py file from the root directory
    agent_path = os.path.join(os.path.dirname(__file__), "agent.py")
    return send_file(agent_path, as_attachment=True, download_name="agent.py")

@app.route("/api/agent/sync", methods=["POST"])
@limiter.exempt
def agent_sync():
    api_key = request.headers.get("X-API-Key")
    if not api_key: return jsonify({"error": "missing api key"}), 401
    
    conn = get_db()
    agent = conn.execute("SELECT id FROM agents WHERE api_key=?", (api_key,)).fetchone()
    if not agent:
        conn.close()
        return jsonify({"error": "invalid api key"}), 401
        
    agent_id = agent["id"]
    data = request.get_json() or {}
    stats = data.get("stats", {})
    new_alerts = data.get("alerts", [])
    
    alerts_triggered = stats.get("alerts_triggered", 0)
    conn.execute("UPDATE agent_stats SET stats_json=?, alerts_triggered=? WHERE agent_id=?", 
                 (json.dumps(stats), alerts_triggered, agent_id))
    conn.execute("UPDATE agents SET last_seen=datetime('now') WHERE id=?", (agent_id,))
    
    for a in new_alerts:
        conn.execute("INSERT OR IGNORE INTO alerts (id, timestamp, alert_type, severity, source_ip, dest_ip, description, packet_count, details, agent_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (a["id"], a["timestamp"], a["alert_type"], a["severity"], a["source_ip"], a["dest_ip"], a["description"], a["packet_count"], json.dumps(a.get("details", {})), agent_id))
        
        # Fire Webhook if configured
        webhook_url = CONFIG.get("WEBHOOK_URL")
        if webhook_url and a["severity"] in ["CRITICAL", "HIGH"]:
            def send_webhook(url, alert_data):
                try:
                    payload = {
                        "content": f"🚨 **IDS ALERT [{alert_data['severity']}]** 🚨\n**Type:** {alert_data['alert_type']}\n**Source:** {alert_data['source_ip']}\n**Desc:** {alert_data['description']}"
                    }
                    requests.post(url, json=payload, timeout=5)
                except:
                    pass
            threading.Thread(target=send_webhook, args=(webhook_url, a), daemon=True).start()
             
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@app.route("/api/config", methods=["GET"])
@login_required
def get_config():
    return jsonify({k:v for k,v in CONFIG.items() if "PASSWORD" not in k})

@app.route("/api/config", methods=["POST"])
@login_required
@admin_required
def update_config():
    data = request.get_json()
    allowed = ["PORT_SCAN_THRESHOLD","PORT_SCAN_WINDOW","DDOS_PPS_THRESHOLD","DDOS_WINDOW",
               "SYN_FLOOD_THRESHOLD","ICMP_FLOOD_THRESHOLD","ABNORMAL_PACKET_SIZE",
               "EMAIL_ENABLED","EMAIL_SENDER","EMAIL_PASSWORD","EMAIL_RECIPIENT",
               "EMAIL_COOLDOWN","VT_API_KEY","DEMO_MODE","INTERFACE",
               "WEBHOOK_URL", "IPS_MODE_ENABLED", "AI_MODE_ENABLED", "GEMINI_API_KEY"]
    conn = get_db()
    for k, v in data.items():
        if k in allowed:
            CONFIG[k] = v
            conn.execute("INSERT OR REPLACE INTO config_store (key,value) VALUES (?,?)", (k, json.dumps(v)))
            if k == "GEMINI_API_KEY":
                rag_engine.configure(v)
    conn.commit(); conn.close()
    return jsonify({"status":"ok"})

@app.route("/api/geoip/bulk", methods=["POST"])
@login_required
def geoip_bulk():
    ips = request.get_json().get("ips", [])
    results = {}
    for ip in ips[:15]:
        if ip.startswith(("192.168.","10.","172.","127.")):
            results[ip] = {"status":"private","country":"Private Network","lat":0,"lon":0}
            continue
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp"
            req = urllib.request.Request(url, headers={"User-Agent":"IDS-Sentinel/1.0"})
            with urllib.request.urlopen(req, timeout=5) as r:
                results[ip] = json.loads(r.read().decode())
            time.sleep(0.1)
        except Exception as e:
            results[ip] = {"status":"fail","error":str(e)}
    return jsonify(results)

@app.route("/api/virustotal/<ip>")
@login_required
def virustotal(ip):
    if ip in VT_CACHE:
        res, ts = VT_CACHE[ip]
        if time.time() - ts < 3600:
            res["cached"] = True; return jsonify(res)
    vt_key = CONFIG.get("VT_API_KEY","")
    if not vt_key: return jsonify({"error":"No VT API key. Add in CONFIG."})
    if not can_vt_request():
        wait = 60 - (time.time() - vt_request_times[0])
        return jsonify({"error":f"Rate limited. Wait {wait:.0f}s.","rate_limited":True})
    try:
        record_vt_request()
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        # pyrefly: ignore [bad-argument-type]
        req = urllib.request.Request(url, headers={"x-apikey":vt_key,"User-Agent":"IDS-Sentinel/1.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
        attrs = data.get("data",{}).get("attributes",{})
        stats = attrs.get("last_analysis_stats",{})
        result = {"ip":ip,"malicious":stats.get("malicious",0),"suspicious":stats.get("suspicious",0),
                  "harmless":stats.get("harmless",0),"undetected":stats.get("undetected",0),
                  "country":attrs.get("country","Unknown"),"owner":attrs.get("as_owner","Unknown"),
                  "reputation":attrs.get("reputation",0),"tags":attrs.get("tags",[]),"cached":False}
        VT_CACHE[ip] = (result, time.time())
        return jsonify(result)
    except urllib.error.HTTPError as e:
        return jsonify({"error":f"VT error: {e.code}"})
    except Exception as e:
        return jsonify({"error":str(e)})

@app.route("/api/vt/status")
@login_required
def vt_status():
    now = time.time()
    recent = [t for t in vt_request_times if now-t < 60]
    return jsonify({"requests_used":len(recent),"requests_remaining":max(0,4-len(recent)),
                    "cache_size":len(VT_CACHE),"key_configured":bool(CONFIG.get("VT_API_KEY"))})

@app.route("/api/stream")
@login_required
def stream():
    agent_id = request.args.get("agent_id")
        
    def gen():
        if not agent_id:
            yield "data: " + json.dumps({"error":"No agent selected"}) + "\n\n"
            return
            
        conn = get_db()
        try:
            last_count_row = conn.execute("SELECT alerts_triggered FROM agent_stats WHERE agent_id=?", (agent_id,)).fetchone()
            last_count = last_count_row[0] if last_count_row else 0
        except Exception:
            last_count = 0
        conn.close()
        
        retries = 0
        while True:
            try:
                conn = get_db()
                row = conn.execute("SELECT stats_json, alerts_triggered FROM agent_stats WHERE agent_id=?", (agent_id,)).fetchone()
                if not row:
                    conn.close()
                    yield "data: " + json.dumps({"error":"Agent not found"}) + "\n\n"
                    time.sleep(2)
                    continue
                    
                stats = json.loads(row["stats_json"]) if row["stats_json"] else {}
                curr_count = row["alerts_triggered"]
                
                new = []
                if curr_count > last_count:
                    limit = curr_count - last_count
                    try:
                        r_alerts = conn.execute("SELECT * FROM alerts WHERE agent_id=? ORDER BY timestamp DESC LIMIT ?", (agent_id, limit)).fetchall()
                        for r in reversed(r_alerts):
                            d = dict(r)
                            d["details"] = json.loads(d.get("details") or "{}")
                            new.append(d)
                    except Exception: pass
                    last_count = curr_count
                    
                conn.close()
                yield "data: " + json.dumps({"stats":stats, "new_alerts":new}) + "\n\n"
                retries = 0; time.sleep(1)
            except GeneratorExit: break
            except Exception as e: print("Stream error:", e); retries += 1; time.sleep(min(retries, 5))
            
    # pyrefly: ignore [no-matching-overload]
    return Response(stream_with_context(gen()), mimetype="text/event-stream", headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.route("/api/rag/analyze", methods=["POST"])
@login_required
def rag_analyze():
    data = request.get_json() or {}
    alert_id = data.get("alert_id")
    if not alert_id:
        return jsonify({"error": "alert_id is required"}), 400
        
    conn = get_db()
    row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    conn.close()
    
    if not row:
        return jsonify({"error": "Alert not found"}), 404
        
    alert_data = dict(row)
    result = rag_engine.analyze_alert(alert_data)
    return jsonify(result)

@app.route("/api/rag/chat", methods=["POST"])
@login_required
def rag_chat():
    data = request.get_json() or {}
    query = data.get("query")
    if not query:
        return jsonify({"error": "query is required"}), 400
        
    result = rag_engine.chat(query)
    return jsonify(result)

if __name__ == "__main__":
    print("\n\033[1;96m    IDS//SENTINEL v3\033[0m")
    print("\033[92m    http://localhost:8080\033[0m")
    print("\033[93m    Login: admin / admin123\033[0m\n")
    app.run(debug=False, host="0.0.0.0", port=8080, threaded=True)
