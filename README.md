# 🔍 NetSentinel — Deep Packet Inspection Engine

> A full-featured network security system with real-time threat detection, traffic classification, content filtering, and behavioral anomaly scoring — built in C++, Python, and React.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-netsentinel--zeta.vercel.app-blue?style=flat-square&logo=vercel)](https://netsentinel-zeta.vercel.app)
[![C++17](https://img.shields.io/badge/C++-17-00599C?style=flat-square&logo=c%2B%2B)](https://isocpp.org/)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

**[🚀 Live Dashboard →](https://netsentinel-zeta.vercel.app)**

---

## 🏗️ Architecture

---

## ✨ Features

| Feature | Description |
|---|---|
| **Protocol Dissector** | Parses L2–L7: Ethernet, IPv4, TCP/UDP, HTTP, DNS, TLS (SNI extraction) |
| **Threat Detector** | Signature-based detection: port scans, SQL injection, XSS, malware C2 beacons |
| **Traffic Classifier** | Identifies applications by L7 payload patterns |
| **Content Filter** | HTTP keyword blocking + DNS-based domain blocklists |
| **Behavioral Profiler ★** | Per-IP baseline profiling with z-score anomaly detection — catches zero-day threats |
| **Demo Mode** | Replays `.pcap` files — no root access needed |
| **Live Dashboard** | React + WebSocket real-time dashboard deployed on Vercel |

---

## 🧠 Behavioral Profiler (Unique Feature)

The profiler builds a **per-IP baseline** over time using Welford's online algorithm and flags deviations using z-score analysis — no ML framework required.

**Metrics tracked per IP:**
- Traffic volume (bytes/min)
- Packet rate
- Unique destination ports
- Protocol distribution ratio
- Active hours pattern

**Anomaly scoring:**
Score > 3.5 → alert generated with full deviation breakdown.

**Example alert:**
```json
{
  "ip": "192.168.1.42",
  "anomaly_score": 4.7,
  "verdict": "POSSIBLE_EXFILTRATION",
  "deviations": [
    { "metric": "bytes_sent", "description": "820% above baseline", "z_score": 4.2 },
    { "metric": "active_hour", "description": "3am (never seen before)", "z_score": 3.5 }
  ]
}
```

---

## 📁 Project Structure
---

## 🚀 Quick Start

### Prerequisites
```bash
# Ubuntu / WSL
sudo apt install build-essential cmake libpcap-dev python3-pip nodejs
```

### 1. Build C++ Engine
```bash
cd engine && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### 2. Run in Demo Mode (no root needed)
```bash
./netsentinel --demo ../../demo/sample.pcap
```

### 3. Start FastAPI Bridge
```bash
cd bridge
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### 4. Start Dashboard
```bash
cd dashboard
npm install && npm run dev
# Open http://localhost:5173
```

### 5. Run all together
Open 3 terminals — bridge, engine, dashboard — then visit `http://localhost:5173`.

---

## 🌐 Deployment

| Layer | Platform | URL |
|---|---|---|
| Dashboard | Vercel | [netsentinel-zeta.vercel.app](https://netsentinel-zeta.vercel.app) |
| Bridge | Local / VPS | `http://localhost:8000` |
| Engine | Local (WSL/Linux) | Runs on host machine |

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Packet Capture | `libpcap` |
| DPI Engine | `C++17` |
| API Bridge | `Python FastAPI` + WebSocket |
| Frontend | `React 18` + `Recharts` |
| Build System | `CMake` |
| CI/CD | `GitHub Actions` |
| Deployment | `Vercel` |

---

## 📄 License

MIT © [Pranit Pawar](https://github.com/pranitpawar24)
