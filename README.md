# 🛡️ Sentinel IDS: AI-Powered Network Defense

Welcome to the **Sentinel Intrusion Detection and Prevention System**. Sentinel is an enterprise-grade, real-time network security dashboard built with a Modern Web Stack (Next.js & FastAPI) and Machine Learning (Random Forest).

## 🌟 Key Features
- **Real-Time Traffic Analysis:** Uses `scapy` for live packet-sniffing and analysis on your network interfaces.
- **AI Threat Modeling:** Integrated Random Forest pipeline leveraging `scikit-learn` to classify DDoS, DoS Hulk, FTP-Patator, and more.
- **Glassmorphic UI Engine:** Stunning React/Next.js interface with real-time continuous WebSockets streaming.
- **IPS Auto-Mitigation Engine:** Automatic threat blocking mechanisms capable of cutting off blacklisted IPs the second they behave maliciously.
- **Portable Executable Build:** The entire application (Next.js UI + FastAPI + ML models) is packaged inside a single standalone `.exe`.

## 🛠️ Tech Stack
- **Frontend**: Next.js 14, React 18, TailwindCSS, Recharts
- **Backend / Core**: FastAPI, Uvicorn, Asyncio, WebSockets
- **Machine Learning**: Scikit-Learn, Pandas, Joblib
- **Packet Engineering**: Scapy, Npcap (Windows)

## ⚡ How to Run from Source Code
1. Make sure Python 3.10+ and Node.js are installed. Ensure Npcap (via Wireshark or standalone) is installed for Scapy packet sniffing capabilities.
2. Clone this repository.
3. Start the Next.js Frontend Development Server:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
4. Start the FastAPI + ML Backend:
   ```bash
   pip install -r requirements.txt # (Make sure you install the required packages)
   python api.py
   ```
The dashboard will be available at `http://localhost:3000` (development) or `http://localhost:8000` (production packaged).

## 🚀 Double-Click Production Executable
We offer a single `.exe` executable that packs the entire UI and ML dependencies. No Node.js or `npm` necessary!
1. Download `Sentinel_IDS.exe`.
2. Double-click it and wait ~15-20 seconds.
3. The server natively powers up and automatically brings up your web browser to the correct page.

## 📄 License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
