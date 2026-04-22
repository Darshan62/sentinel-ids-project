import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import joblib
import time
import os
import csv
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
from realtime_capture import extract_features, start_sniffing

# ===============================
# PAGE CONFIG 
# ===============================
st.set_page_config(
    page_title="Sentinel IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ===============================
# CONFIG & LOAD MODEL
# ===============================
PROJECT_ROOT = r"E:\IDS IPS Project"
MODEL_DIR = os.path.join(PROJECT_ROOT, "models")
DATA_PATH = os.path.join(PROJECT_ROOT, "data", "balanced_final_dataset.csv")
LOG_FILE = os.path.join(PROJECT_ROOT, "detection_logs.csv")

MODEL_PATH = os.path.join(MODEL_DIR, "best_model.pkl")
FEATURE_PATH = os.path.join(MODEL_DIR, "features.pkl")

os.makedirs(PROJECT_ROOT, exist_ok=True)

@st.cache_resource
def load_model_data():
    try:
        model = joblib.load(MODEL_PATH)
        feature_columns = joblib.load(FEATURE_PATH)
        return model, feature_columns, True
    except Exception as e:
        return None, None, False

model, feature_columns, is_loaded = load_model_data()

# ===============================
# LOAD EXTERNAL HTML & CSS
# ===============================
def load_asset(filename):
    path = os.path.join(os.path.dirname(__file__), "dashboard_assets", filename)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return ""

STYLE_CSS = load_asset("style.css")
LAYOUT_HTML = load_asset("layout.html")
SCRIPT_JS = load_asset("script.js")

# Modify Streamlit's native sidebar and buttons styling to blend perfectly with our dark layout.
st.markdown("""
<style>
/* FORCE DARK MODE IF CONFIG.TOML FAILS */
html, body, [data-testid="stAppViewContainer"], .stApp {
    background-color: #0c1324 !important;
}
header[data-testid="stHeader"] { display: none; }
/* PREVENT SCROLL RESET COLLAPSE BY LOCKING MIN-HEIGHT */
.block-container { padding-top: 1rem !important; max-width: 100% !important; min-height: 2000px !important; }
section[data-testid="stSidebar"] { background-color: #151b2d !important; border-right: 1px solid rgba(69, 70, 77, 0.05) !important; color:#dce1fb !important; }

/* Override Streamlit Buttons to match Stitch Sidebar */
div.stButton > button[kind="primary"] {
    background: #7bd0ff !important;
    color: #00354a !important;
    border: none !important;
    font-family: 'Space Grotesk', monospace !important;
    font-weight: 700 !important;
    font-size: 12px !important;
    letter-spacing: 0.1em !important;
    border-radius: 12px !important;
    text-transform: uppercase !important;
    padding: 12px !important;
}
div.stButton > button[kind="secondary"] {
    background: transparent !important;
    color: #7bd0ff !important;
    border: 1px solid rgba(123, 208, 255, 0.2) !important;
    font-family: 'Space Grotesk', monospace !important;
    font-weight: 700 !important;
    font-size: 12px !important;
    letter-spacing: 0.1em !important;
    border-radius: 12px !important;
    text-transform: uppercase !important;
    padding: 12px !important;
}
</style>
""", unsafe_allow_html=True)


# ===============================
# DATA & TRANSLATIONS
# ===============================
PROTOCOL_MAP = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
LABEL_MAP = {0: "Safe", 1: "DDoS", 2: "DoS GoldenEye", 3: "DoS Hulk", 4: "DoS slowloris", 5: "FTP-Patator", 6: "SSH-Patator"}

def clean_protocol(proto):
    return PROTOCOL_MAP.get(proto, str(proto))

import socket
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

def predict_row(row):
    row_df = pd.DataFrame([row])
    row_df = row_df.reindex(columns=feature_columns, fill_value=0)
    return model.predict(row_df)[0]

def log_to_csv(log_data):
    file_exists = os.path.isfile(LOG_FILE)
    with open(LOG_FILE, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["Timestamp", "Activity", "Meaning", "Protocol", "Port", "Status"], extrasaction='ignore')
        if not file_exists: writer.writeheader()
        writer.writerow(log_data)

# ===============================
# PLOTLY & HTML INJECTION
# ===============================
def generate_plotly_html_string(safe, attack, packet_list):
    # Pie Chart
    if safe == 0 and attack == 0: safe, attack = 1, 0
    df_pie = pd.DataFrame({'Category': ['Safe', 'Attack'], 'Value': [safe, attack]})
    pie = px.pie(df_pie, values='Value', names='Category', hole=0.75, color='Category', color_discrete_map={'Safe': '#7bd0ff', 'Attack': '#ffb4ab'})
    efficacy = int((safe / (safe+attack) * 100)) if (safe+attack) > 0 else 100
    pie.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#aeb9d0", showlegend=False, margin=dict(t=0, b=0, l=0, r=0), height=300,
        annotations=[dict(text=f"<span style='font-size:36px; font-weight:800; color:#dce1fb;'>{efficacy}%</span><br><span style='font-size:10px; letter-spacing:0.1em; color:#c6c6cd;'>EFFICACY</span>", x=0.5, y=0.5, showarrow=False)])
    pie_html = pie.to_html(full_html=False, include_plotlyjs='cdn', config={'displayModeBar': False})

    # Line Chart
    hist_df = pd.DataFrame([{"Time": p["Timestamp"], "Status": p["Status"]} for p in packet_list[-50:]]) if packet_list else pd.DataFrame()
    if hist_df.empty: line = go.Figure()
    else: line = px.bar(hist_df.groupby(['Time', 'Status']).size().reset_index(name='Count'), x="Time", y="Count", color="Status", color_discrete_map={'🟢 Safe': '#7bd0ff', '🔴 Attack': '#ffb4ab'}, barmode='stack', opacity=0.8)
    line.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#aeb9d0", margin=dict(t=10, b=10, l=10, r=10), height=300, xaxis=dict(showgrid=False), yaxis=dict(showgrid=False, visible=False), showlegend=False)
    line_html = line.to_html(full_html=False, include_plotlyjs=False, config={'displayModeBar': False}) # only include JS once
    
    return pie_html, line_html


def render_full_dashboard(total, safe, suspicious, attack, packet_list):
    safe_pct = f"{(safe / total * 100):.1f}" if total > 0 else "100.0"
    
    badge_html = '''<div class="status-badge-secure"><span style="width:8px; height:8px; border-radius:50%; background:#7bd0ff; display:inline-block;"></span><span class="font-label" style="font-size:10px; color:#7bd0ff; font-weight: 700;">🟢 System Secure</span></div>''' if attack == 0 else '''<div class="status-badge-threat"><span class="animate-pulse-err" style="width:8px; height:8px; border-radius:50%; background:#ffb4ab; display:inline-block;"></span><span class="font-label" style="font-size:10px; color:#ffb4ab; font-weight: 700;">🔴 Threat Detected</span></div>'''
    
    alert_pulse = "animate-pulse-err" if attack > 0 else ""

    table_rows = ""
    for p in reversed(packet_list[-10:]):
        bg = "background-color: rgba(255, 180, 171, 0.05);" if p["Classification"] == "Attack" else ""
        text_proto = "color: #ffb4ab; font-weight: 700;" if p["Classification"] == "Attack" else "color: #7bd0ff; font-weight: 700;"
        status_html = f'''<span class="flex align-center gap-2" style="color:#ffb4ab;"><span class="animate-pulse-err" style="width:6px; height:6px; border-radius:50%; background:#ffb4ab;"></span>{p["Status"]}</span>''' if p["Classification"] == "Attack" else f'''<span class="flex align-center gap-2" style="color:#7bd0ff;"><span style="width:6px; height:6px; border-radius:50%; background:#7bd0ff;"></span>{p["Status"]}</span>'''
        time_c = "#ffb4ab" if p["Classification"] == "Attack" else "#c6c6cd"
        # No indentation matching here, just flat HTML
        table_rows += f"<tr style='{bg}'><td style='color:{time_c}'>{p['Timestamp']}</td><td style='{text_proto}'>{p['Activity']} ({p['Protocol']})</td><td>{p['Meaning']}</td><td>{status_html}</td></tr>"

    alerts_html = ""
    if attack > 0:
        alerts_html += '''<div style="background:rgba(147,0,10,0.2); padding:16px; border-radius:16px; border:1px solid rgba(255,180,171,0.2); box-shadow:0 0 15px rgba(255,180,171,0.15); margin-bottom:16px;"><div class="flex justify-between align-center" style="margin-bottom:8px;"><span class="font-label" style="color:#ffb4ab; font-size:10px; font-weight:700;">⚠️ Attack Detected!</span><span style="font-size:10px; color:rgba(255,180,171,0.6);">JUST NOW</span></div><p style="font-size:12px; font-weight:500; color:#ffdad6; margin:0;">Threat mitigation triggered. Incident logged to CSV.</p></div>'''
    alerts_html += '''<div style="background:rgba(46,52,71,0.5); padding:16px; border-radius:16px; border:1px solid rgba(69,70,77,0.1); margin-bottom:16px;"><div class="flex justify-between align-center" style="margin-bottom:8px;"><span class="font-label" style="color:#7bd0ff; font-size:10px; font-weight:700;">System Notice</span><span style="font-size:10px; color:#c6c6cd;">ACTIVE</span></div><p style="font-size:12px; font-weight:500; color:#dce1fb; margin:0;">Network scanning and ML Engine linked.</p></div>'''

    pie_html, line_html = generate_plotly_html_string(safe, attack, packet_list)

    rendered = LAYOUT_HTML \
        .replace("{{ CSS_CONTENT }}", STYLE_CSS) \
        .replace("{{ JS_CONTENT }}", SCRIPT_JS) \
        .replace("{{ BADGE_HTML }}", badge_html) \
        .replace("{{ TOTAL }}", str(total)) \
        .replace("{{ SAFE_PCT }}", safe_pct) \
        .replace("{{ SUSPICIOUS }}", str(suspicious)) \
        .replace("{{ ATTACK }}", str(attack)) \
        .replace("{{ ALERT_PULSE_CLASS }}", alert_pulse) \
        .replace("{{ TABLE_ROWS }}", table_rows) \
        .replace("{{ ALERTS_HTML }}", alerts_html) \
        .replace("{{ PIE_CHART }}", pie_html) \
        .replace("{{ LINE_CHART }}", line_html)
        
    components.html(rendered, height=1800, scrolling=False)


# ===============================
# MAIN UI FLOW
# ===============================

if os.path.exists(DATA_PATH): feature_df = pd.read_csv(DATA_PATH)
else: feature_df = None

# Custom Sidebar HTML matching Design
st.sidebar.markdown('''
<div style="display:flex; align-items:center; gap:12px; margin-bottom:32px;">
    <div style="width:40px; height:40px; border-radius:12px; background:#2e3447; display:flex; align-items:center; justify-content:center; color:#7bd0ff;">
        <span class="material-symbols-outlined">security</span>
    </div>
    <div>
        <p style="font-family:'Space Grotesk'; font-size:12px; font-weight:600; text-transform:uppercase; letter-spacing:0.1em; color:#dce1fb; margin:0;">NODE-01</p>
        <p style="font-family:'Space Grotesk'; font-size:10px; color:#c6c6cd; margin:0;">US-EAST-SHIELD</p>
    </div>
</div>
<div style="display:flex; flex-direction:column; gap:8px;">
    <div style="display:flex; align-items:center; gap:16px; padding:12px 24px; background:linear-gradient(to right, rgba(123,208,255,0.1), transparent); color:#7bd0ff; border-left:4px solid #7bd0ff;">
        <span class="material-symbols-outlined">dashboard</span>
        <span style="font-family:'Space Grotesk'; font-size:12px; font-weight:600; text-transform:uppercase; letter-spacing:0.1em;">Overview</span>
    </div>
    <div style="display:flex; align-items:center; gap:16px; padding:12px 24px; color:rgba(220,225,251,0.4);">
        <span class="material-symbols-outlined">lan</span>
        <span style="font-family:'Space Grotesk'; font-size:12px; font-weight:600; text-transform:uppercase; letter-spacing:0.1em;">Network Traffic</span>
    </div>
</div>
<br><br>
''', unsafe_allow_html=True)

start_sim = st.sidebar.button("▶ START SIMULATION", type="primary", use_container_width=True)
start_live = st.sidebar.button("📡 LIVE MONITORING", type="secondary", use_container_width=True)

layout_ph = st.empty()

# Initial Render
with layout_ph.container():
    render_full_dashboard(1200000, 1180800, 142, 12, [])

if start_sim:
    if feature_df is None: st.error("❌ Dataset not found.")
    else:
        packet_data = []
        metrics = {"total": 0, "safe": 0, "attack": 0}
        
        for i in range(10000):
            row = feature_df.sample(1).iloc[0]
            pred = predict_row(row)
            is_attack = (pred != 0)
            label_name = LABEL_MAP.get(pred, "Unknown")
            metrics["total"] += 1
            if is_attack: metrics["attack"] += 1
            else: metrics["safe"] += 1
            
            curr_time = datetime.now().strftime("%H:%M:%S")
            raw_port = row.get("Dst Port", 0)
            act, meaning = get_activity_and_insight(raw_port, pred)
            
            p_data = {
                "Timestamp": curr_time, "Protocol": clean_protocol(row.get("Protocol", "TCP")),
                "Port": get_port_label(raw_port), "Activity": act, "Meaning": meaning,
                "Classification": "Attack" if is_attack else "Safe", "Status": f"Attack ({label_name})" if is_attack else "Safe"
            }
            packet_data.append(p_data)
            log_to_csv(p_data)
            
            with layout_ph.container():
                render_full_dashboard(metrics["total"], metrics["safe"], metrics["attack"], metrics["attack"], packet_data)
            
            time.sleep(1.0)
            
elif start_live:
    packet_data = []
    metrics = {"total": 0, "safe": 0, "attack": 0}
    
    def process_packet(packet):
        features = extract_features(packet)
        if features:
            df = pd.DataFrame([features])
            df = df.reindex(columns=feature_columns, fill_value=0)
            pred = model.predict(df)[0]
            
            is_attack = (pred != 0)
            label_name = LABEL_MAP.get(pred, "Unknown")
            metrics["total"] += 1
            if is_attack: metrics["attack"] += 1
            else: metrics["safe"] += 1
            
            curr_time = datetime.now().strftime("%H:%M:%S")
            raw_port = features.get("Dst Port", 0)
            act, meaning = get_activity_and_insight(raw_port, pred)
            
            p_data = {
                "Timestamp": curr_time, "Protocol": clean_protocol(features.get("Protocol", 0)),
                "Port": get_port_label(raw_port), "Activity": act, "Meaning": meaning,
                "Classification": "Attack" if is_attack else "Safe", "Status": f"Attack ({label_name})" if is_attack else "Safe"
            }
            packet_data.append(p_data)
            log_to_csv(p_data)
            
            with layout_ph.container():
                render_full_dashboard(metrics["total"], metrics["safe"], metrics["attack"], metrics["attack"], packet_data)
            
    start_sniffing(process_packet, packet_count=10000)