import os
import sys
import joblib
import pandas as pd
import asyncio
import uuid
import datetime
import webbrowser
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import socket
from realtime_capture import extract_features, start_sniffing, stop_sniffing
import threading
import logging

app = FastAPI(title="Sentinel IDS API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if getattr(sys, 'frozen', False):
    base_path = sys._MEIPASS
else:
    base_path = os.path.dirname(os.path.abspath(__file__))

PROJECT_ROOT = base_path
MODEL_DIR = os.path.join(PROJECT_ROOT, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "best_model.pkl")
FEATURE_PATH = os.path.join(MODEL_DIR, "features.pkl")

# Load ML Model
try:
    model = joblib.load(MODEL_PATH)
    feature_columns = joblib.load(FEATURE_PATH)
    is_loaded = True
    print("[SUCCESS] Model loaded successfully.")
except Exception as e:
    print(f"[ERROR] Failed to load model: {e}")
    model = None
    feature_columns = None
    is_loaded = False

# Mapping
PROTOCOL_MAP = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
LABEL_MAP = {0: "Safe", 1: "DDoS", 2: "DoS GoldenEye", 3: "DoS Hulk", 4: "DoS slowloris", 5: "FTP-Patator", 6: "SSH-Patator"}

def clean_protocol(proto):
    return PROTOCOL_MAP.get(proto, str(proto))

def get_port_label(port):
    try: port = int(float(port))
    except: return "Network Port"
    common_map = {443: 'HTTPS', 80: 'HTTP', 53: 'DNS', 22: 'SSH', 21: 'FTP', 3389: 'RDP'}
    if port in common_map: return f'{port} ({common_map[port]})'
    try: return f"{port} ({socket.getservbyport(port).upper()})"
    except: return f'{port} (Standard)'

def get_activity_and_insight(port, pred):
    is_attack = (pred != 0)
    label_name = LABEL_MAP.get(pred, "Threat")
    try: port = int(float(port))
    except: port = 0
    if port == 443: return "🌐 Secure Web", "Encrypted HTTPS activity." if not is_attack else f"HTTPS payload threat! ({label_name})"
    elif port == 80: return "🌐 Web Traffic", "Standard HTTP." if not is_attack else f"Suspicious HTTP attack! ({label_name})"
    elif port == 53: return "🔍 DNS Lookup", "Routine address lookup." if not is_attack else f"DNS anomaly detected! ({label_name})"
    elif port == 22: return "🔐 Remote Access", "Standard SSH." if not is_attack else f"SSH breach attempt! ({label_name})"
    else: return "📡 Network Data", "Network communication." if not is_attack else f"Malicious protocol pattern! ({label_name})"

# Threat Intelligence & IPS State
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "threat_logs.csv")
BLOCKED_IPS = set()
IP_ATTACK_HISTORY = {} # {ip: [timestamp1, timestamp2]}
ML_STATS = {"processed": 0, "latency_ms_avg": 24.5, "uptime": datetime.datetime.now()}


# Connect WebSockets
active_connections = []

@app.websocket("/ws/live-traffic")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)

from fastapi import Body
from fastapi.responses import FileResponse

@app.get("/api/logs/download")
def download_logs():
    if not os.path.exists(LOG_FILE):
        # Create an empty CSV with headers if no threats have been logged yet
        pd.DataFrame(columns=["Timestamp", "Src IP", "Protocol", "Port", "Activity", "Status", "Attack Label"]).to_csv(LOG_FILE, index=False)
    return FileResponse(path=LOG_FILE, filename="threat_logs.csv", media_type="text/csv")

@app.get("/api/logs")
def get_logs():
    if not os.path.exists(LOG_FILE):
        return {"status": "error", "message": "Log file not found"}
    try:
        df = pd.read_csv(LOG_FILE)
        # Summaries for charts
        protocol_counts = df["Protocol"].value_counts().to_dict()
        status_counts = df["Status"].value_counts().to_dict()
        recent_logs = df.tail(100).fillna("").to_dict(orient="records")
        return {
            "protocols": [{"name": k, "value": v} for k, v in protocol_counts.items()],
            "statuses": [{"name": k, "value": v} for k, v in status_counts.items()],
            "logs": recent_logs[::-1]  # Reverse to show newest first
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/block_ip")
def block_ip(payload: dict = Body(...)):
    ip = payload.get("ip")
    if ip:
        BLOCKED_IPS.add(ip)
        return {"status": "success", "message": f"IP {ip} added to IPS blocklist."}
    return {"status": "error", "message": "No IP provided."}

@app.get("/api/health")
def get_health():
    uptime = datetime.datetime.now() - ML_STATS["uptime"]
    return {
        "status": "Healthy" if is_loaded else "Degraded",
        "processed_packets": ML_STATS["processed"],
        "avg_latency_ms": ML_STATS["latency_ms_avg"],
        "active_blocks": len(BLOCKED_IPS),
        "uptime_seconds": uptime.total_seconds(),
        "is_sniffing": is_sniffing_active
    }

@app.post("/api/inject_attack")
async def inject_attack(payload: dict = Body(...)):
    attack_type = payload.get("type", "DoS Hulk")
    
    # Map common attacks to the correct string representation
    label_map_rev = {v: k for k, v in LABEL_MAP.items()}
    pred_code = label_map_rev.get(attack_type, 1)
    
    curr_time = datetime.datetime.now().strftime("%H:%M:%S")
    dummy_ip = f"192.168.1.{payload.get('ip_suffix', '224')}"
    
    # IPS Auto-Block Logic for Simulator
    if dummy_ip not in BLOCKED_IPS:
        now = datetime.datetime.now()
        if dummy_ip not in IP_ATTACK_HISTORY:
            IP_ATTACK_HISTORY[dummy_ip] = []
        IP_ATTACK_HISTORY[dummy_ip] = [t for t in IP_ATTACK_HISTORY[dummy_ip] if (now - t).total_seconds() <= 5]
        IP_ATTACK_HISTORY[dummy_ip].append(now)
        if len(IP_ATTACK_HISTORY[dummy_ip]) > 2:
            BLOCKED_IPS.add(dummy_ip)
            print(f"[IPS] Auto-blocked {dummy_ip} due to frequent attacks (Simulated)")

    if dummy_ip in BLOCKED_IPS:
        act, meaning = "🛡️ IPS Mitigated", "Connection dropped automatically limit exceeded."
        status_val = "Blocked"
    else:
        act = payload.get("activity", "🚨 INJECTED THREAT")
        meaning = "Simulated Threat Injection payload triggered."
        status_val = "Attack"

    data = {
        "id": str(uuid.uuid4()),
        "timestamp": curr_time,
        "src_ip": dummy_ip,
        "protocol": "TCP",
        "port": get_port_label(payload.get("port", 80)),
        "activity": act,
        "meaning": meaning,
        "status": status_val,
        "attackLabel": attack_type if status_val == "Attack" else ""
    }

    # Threat Logger CSV Export for Simulator
    if status_val == "Attack" or status_val == "Blocked":
        log_df = pd.DataFrame([{
            "Timestamp": data["timestamp"],
            "Src IP": data["src_ip"],
            "Protocol": data["protocol"],
            "Port": data["port"],
            "Activity": data["activity"],
            "Status": data["status"],
            "Attack Label": data["attackLabel"]
        }])
        log_df.to_csv(LOG_FILE, mode='a', header=not os.path.exists(LOG_FILE), index=False)
    
    # Broadcast manually
    ML_STATS["processed"] += 1
    for connection in active_connections:
        try:
            await connection.send_json(data)
        except Exception:
            pass
            
    return {"status": "success", "injected": data}

# Background Sniffer Loop
def start_background_sniffer():
    def process_packet(packet):
        features = extract_features(packet)
        if features and is_loaded:
            df = pd.DataFrame([features])
            df = df.reindex(columns=feature_columns, fill_value=0)
            pred = model.predict(df)[0]
            
            is_attack = (pred != 0)
            curr_time = datetime.datetime.now().strftime("%H:%M:%S")
            raw_port = features.get("Dst Port", 0)
            src_ip = features.get("Src IP", "0.0.0.0")
            
            ML_STATS["processed"] += 1
            
            # Auto-Block Logic (Basic IPS)
            if is_attack and src_ip not in BLOCKED_IPS:
                now = datetime.datetime.now()
                if src_ip not in IP_ATTACK_HISTORY:
                    IP_ATTACK_HISTORY[src_ip] = []
                IP_ATTACK_HISTORY[src_ip] = [t for t in IP_ATTACK_HISTORY[src_ip] if (now - t).total_seconds() <= 5]
                IP_ATTACK_HISTORY[src_ip].append(now)
                if len(IP_ATTACK_HISTORY[src_ip]) > 2:
                    BLOCKED_IPS.add(src_ip)
                    print(f"[IPS] Auto-blocked {src_ip} due to frequent attacks")

            if src_ip in BLOCKED_IPS:
                act, meaning = "🛡️ IPS Mitigated", "Connection dropped automatically limit exceeded."
                status_val = "Blocked"
            else:
                act, meaning = get_activity_and_insight(raw_port, pred)
                status_val = "Attack" if is_attack else "Safe"
            
            # Form final Data Object specifically for Next.js UI consumption
            data = {
                "id": str(uuid.uuid4()),
                "timestamp": curr_time,
                "src_ip": src_ip,
                "protocol": clean_protocol(features.get("Protocol", 0)),
                "port": get_port_label(raw_port),
                "activity": act,
                "meaning": meaning,
                "status": status_val,
                "attackLabel": LABEL_MAP.get(pred, "Unknown") if is_attack else ""
            }

            # Threat Logger CSV Export
            if is_attack or status_val == "Blocked":
                log_df = pd.DataFrame([{
                    "Timestamp": data["timestamp"],
                    "Src IP": data["src_ip"],
                    "Protocol": data["protocol"],
                    "Port": data["port"],
                    "Activity": data["activity"],
                    "Status": data["status"],
                    "Attack Label": data["attackLabel"]
                }])
                log_df.to_csv(LOG_FILE, mode='a', header=not os.path.exists(LOG_FILE), index=False)
            
            # Broadcast to UI
            for connection in active_connections:
                try:
                    asyncio.run(connection.send_json(data))
                except RuntimeError:
                    pass # Handled internally by asyncio loop
    # Runs sniffing blocking here, so wrap in thread
    print("[INFO] Started Live Sniffing...")
    try:
        start_sniffing(process_packet, packet_count=1000000)
    except Exception as e:
        print(f"[ERROR] Sniffing failed: {e}")
        curr_time = datetime.datetime.now().strftime("%H:%M:%S")
        error_data = {
            "id": str(uuid.uuid4()),
            "timestamp": curr_time,
            "src_ip": "RENDER_CLOUD",
            "protocol": "SYS",
            "port": "--",
            "activity": "⚠️ CLOUD SNIFFING BLOCKED",
            "meaning": "Live network sniffing requires Root/Admin rights. Not allowed on cloud servers. Please use the Simulator control panel.",
            "status": "Attack",
            "attackLabel": "PERMISSION DENIED"
        }
        for connection in active_connections:
            try:
                asyncio.run(connection.send_json(error_data))
            except:
                pass
is_sniffing_active = True
sniff_thread = None

@app.post("/api/start")
def start_sniff():
    global is_sniffing_active, sniff_thread
    if not is_sniffing_active:
        is_sniffing_active = True
        sniff_thread = threading.Thread(target=start_background_sniffer, daemon=True)
        sniff_thread.start()
        return {"status": "started"}
    return {"status": "already running"}

@app.post("/api/stop")
def stop_sniff():
    global is_sniffing_active
    is_sniffing_active = False
    stop_sniffing()
    return {"status": "stopped"}

@app.on_event("startup")
async def startup_event():
    global is_sniffing_active, sniff_thread
    is_sniffing_active = True
    sniff_thread = threading.Thread(target=start_background_sniffer, daemon=True)
    sniff_thread.start()
    print("[INFO] Launching Sentinel UI in default browser...")
    webbrowser.open("http://127.0.0.1:8000")

frontend_path = os.path.join(base_path, "frontend", "out")
if os.path.isdir(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
