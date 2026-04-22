import subprocess
import webbrowser
import time
import os
import sys

# ===================================
# CONFIGURATION
# ===================================
PROJECT_ROOT = r"E:\IDS IPS Project"
DASHBOARD_PATH = os.path.join(PROJECT_ROOT, "dashboard", "index.html")

# Port for API
PORT = 8000

# ===================================
# STEP 1 — Start FastAPI Backend
# ===================================
print("🚀 Starting FastAPI backend...")

# Build the command to start uvicorn
api_command = [
    sys.executable,  # current Python executable
    "-m", "uvicorn",
    "scripts.api_server:app",
    "--host", "127.0.0.1",
    "--port", str(PORT),
    "--reload"
]

# Start the backend as a background process
backend_process = subprocess.Popen(api_command, cwd=PROJECT_ROOT)

# Give the server a few seconds to start
time.sleep(5)

# ===================================
# STEP 2 — Open Dashboard Automatically
# ===================================
if os.path.exists(DASHBOARD_PATH):
    print(f"🌐 Opening dashboard: {DASHBOARD_PATH}")
    webbrowser.open(f"file:///{DASHBOARD_PATH}")
else:
    print(f"⚠️ Dashboard not found at: {DASHBOARD_PATH}")

# ===================================
# STEP 3 — Keep app running
# ===================================
print("✅ IDS/IPS system is running.")
print("Press Ctrl+C to stop both backend and dashboard.")

try:
    # Keep the script alive while backend runs
    backend_process.wait()
except KeyboardInterrupt:
    print("\n🛑 Stopping backend...")
    backend_process.terminate()
    print("👋 IDS/IPS system stopped.")
