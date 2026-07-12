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

# 🏗️ System Architecture

``` mermaid
flowchart LR

subgraph INPUT["Traffic Sources"]
A1["Live Network"]
A2["PCAP Replay"]
end

subgraph ENGINE["C++ DPI Engine"]
B1["libpcap Capture"]
B2["Protocol Dissector"]
B3["Threat Detection"]
B4["Traffic Classification"]
B5["Content Filter"]
B6["Behavioral Profiler"]
B7["Policy Engine"]
B8["JSON Logger"]
end

subgraph BACKEND["FastAPI Backend"]
C1["REST API"]
C2["WebSocket"]
C3["Scenario Runner"]
end

subgraph DASHBOARD["React Dashboard"]
D1["Scenario Controls"]
D2["Live Packet Feed"]
D3["Analytics"]
D4["Alerts"]
end

A1 --> B1
A2 --> B1
B1 --> B2
B2 --> B3
B2 --> B4
B2 --> B5
B2 --> B6
B3 --> B7
B4 --> B7
B5 --> B7
B6 --> B7
B7 --> B8
B8 --> C1
C1 --> C2
C1 --> C3
C2 --> D2
C2 --> D4
C3 --> D1
C1 --> D3
```

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

# 📁 Project Structure

``` text
netsentinel/
├── engine/
│   ├── include/
│   ├── src/
│   ├── rules/
│   └── CMakeLists.txt
├── bridge/
│   ├── main.py
│   └── requirements.txt
├── dashboard/
│   ├── src/
│   ├── public/
│   └── package.json
├── demo/
├── docs/
├── .github/workflows/
├── LICENSE
└── README.md
```
          # CI: builds C++ engine, tests bridge, builds dashboard

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

---

## 🖥️ How to Use NetSentinel

### Option 1 — Just view the live demo (no setup needed)
Visit **[netsentinel-zeta.vercel.app](https://netsentinel-zeta.vercel.app)** and click any scenario button to see the engine analyzing pre-captured attack traffic in real time.

> **Note:** The live demo shows traffic from our engine running on our server — not your own network traffic. To monitor your own traffic, follow Option 2 or 3 below.

---

### Option 2 — Monitor your own machine's traffic (local setup)

Clone and run the engine on your own machine to analyze your real network traffic.

**Requirements:** Linux or WSL2, `libpcap`, `cmake`, `python3`, `node`

```bash
# 1. Clone
git clone https://github.com/pranitpawar24/netsentinel.git
cd netsentinel

# 2. Build engine
cd engine && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(nproc)

# 3. Start bridge (new terminal)
cd ../../bridge
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000

# 4. Start dashboard (new terminal)
cd ../dashboard
npm install && npm run dev

# 5. Run engine on your network interface (new terminal)
ip a                          # find your interface name (eth0, wlan0, etc.)
sudo ./engine/build/netsentinel --iface eth0 --bridge http://localhost:8000

# 6. Open dashboard
# http://localhost:5173
```

Now the dashboard shows **your own real network traffic** being analyzed live.

---

### Option 3 — Run attack scenarios without live capture (demo mode)

No root access needed — replays pre-captured attack pcap files:

```bash
# Normal traffic
./engine/build/netsentinel --demo demo/normal_traffic.pcap --bridge http://localhost:8000

# Port scan attack
./engine/build/netsentinel --demo demo/port_scan.pcap --bridge http://localhost:8000

# SQL injection
./engine/build/netsentinel --demo demo/sql_injection.pcap --bridge http://localhost:8000

# Data exfiltration
./engine/build/netsentinel --demo demo/exfiltration.pcap --bridge http://localhost:8000
```

Or use the scenario buttons on the dashboard — they trigger these automatically.

---

### Option 4 — Deploy on your own network (advanced)

To monitor all traffic on a network (not just one machine):

1. Deploy the engine + bridge on a Linux machine connected to your network
2. Run engine in live capture mode: `sudo ./netsentinel --iface eth0`
3. Deploy the dashboard on Vercel or any static host
4. Set `VITE_API_URL` to your bridge's public IP
5. Every device on the network is now monitored

> This is how enterprise IDS tools like Snort and Suricata are deployed.

---

## 🎯 Seeing Threats in Action

No technical setup needed. Just visit the live dashboard and click any scenario button:

| Button | What happens | What you see |
|---|---|---|
| **Normal Traffic** | Replays HTTP, DNS, TLS browsing traffic | Clean traffic, no alerts, protocol distribution |
| **Port Scan** | Replays Nmap-style SYN scan on 30 ports | PORT_SCAN alert fires, 30+ packets to same IP |
| **SQL Injection** | Replays SQLi + XSS payloads over HTTP | DROP/ALERT verdicts, injection reason shown |
| **Data Exfiltration** | Replays large upload to foreign IP on port 4444 | Anomaly score rises, POSSIBLE_EXFILTRATION alert |

### What the dashboard shows for each threat

**Port Scan:**
Alert: PORT_SCAN · 10.0.0.99 → 192.168.1.10
Reason: SYN to 30 unique ports
Verdict: ALERT
**SQL Injection:**
Alert: DROP · 10.0.0.55 → victim.com
Reason: SQL Injection attempt detected in POST /login
Payload: ' OR '1'='1
Verdict: DROP

**Data Exfiltration:**
Alert: POSSIBLE_EXFILTRATION · 192.168.1.42
Anomaly score: 4.7
Deviation: 820% above baseline upload volume
Active at unusual hour

> These are real pcap files captured from actual attack patterns,
> replayed through the C++ engine and detected in real time.
