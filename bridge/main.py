from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import time, subprocess, os
from collections import deque

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

events  = deque(maxlen=1000)
alerts  = deque(maxlen=200)
stats   = {"total_packets":0,"total_bytes":0,"threats_detected":0,
           "anomalies_detected":0,"protocols":{},"start_time":time.time()}

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
ENGINE_PATH  = os.path.join(BASE_DIR, "../engine/build/netsentinel")
SCENARIOS    = {
    "normal":         os.path.join(BASE_DIR, "../demo/normal_traffic.pcap"),
    "port-scan":      os.path.join(BASE_DIR, "../demo/port_scan.pcap"),
    "sql-injection":  os.path.join(BASE_DIR, "../demo/sql_injection.pcap"),
    "exfiltration":   os.path.join(BASE_DIR, "../demo/exfiltration.pcap"),
}

engine_process = None

# ─── WebSocket manager ──────────────────────────────────────
class ConnectionManager:
    def __init__(self): self.active = []
    async def connect(self, ws): await ws.accept(); self.active.append(ws)
    def disconnect(self, ws):
        if ws in self.active: self.active.remove(ws)
    async def broadcast(self, msg):
        dead = []
        for ws in self.active:
            try: await ws.send_json(msg)
            except: dead.append(ws)
        for ws in dead:
            if ws in self.active: self.active.remove(ws)

manager = ConnectionManager()

# ─── Models ─────────────────────────────────────────────────
class PacketEvent(BaseModel):
    src_ip: str; dst_ip: str; src_port: int; dst_port: int
    protocol: str; app_protocol: str = ""; host: str = ""
    bytes: int; verdict: str; module: str = ""; reason: str = ""
    timestamp: Optional[float] = None

class AnomalyEvent(BaseModel):
    ip: str; score: float; verdict: str
    deviations: list[dict]; timestamp: Optional[float] = None

# ─── Ingest endpoints (called by C++ engine) ────────────────
@app.post("/ingest/packet")
async def ingest_packet(e: PacketEvent):
    e.timestamp = e.timestamp or time.time()
    d = e.model_dump()
    events.append(d)
    stats["total_packets"] += 1
    stats["total_bytes"]   += e.bytes
    proto = e.app_protocol or e.protocol
    stats["protocols"][proto] = stats["protocols"].get(proto, 0) + 1
    if e.verdict in ("DROP","ALERT"):
        stats["threats_detected"] += 1
        alerts.append({**d, "type":"threat"})
    await manager.broadcast({"type":"packet","data":d})
    return {"ok": True}

@app.post("/ingest/anomaly")
async def ingest_anomaly(e: AnomalyEvent):
    e.timestamp = e.timestamp or time.time()
    d = e.model_dump()
    stats["anomalies_detected"] += 1
    alerts.append({**d, "type":"anomaly"})
    await manager.broadcast({"type":"anomaly","data":d})
    return {"ok": True}

# ─── Scenario endpoint ───────────────────────────────────────
@app.post("/scenario/{name}")
async def run_scenario(name: str):
    global engine_process
    if name not in SCENARIOS:
        return {"error": f"Unknown scenario '{name}'. Valid: {list(SCENARIOS.keys())}"}

    # Kill previous engine run
    if engine_process and engine_process.poll() is None:
        engine_process.terminate()
        try: engine_process.wait(timeout=3)
        except: engine_process.kill()

    # Reset stats and queues
    stats.update({"total_packets":0,"total_bytes":0,
                  "threats_detected":0,"anomalies_detected":0,
                  "protocols":{},"start_time":time.time()})
    events.clear()
    alerts.clear()

    # Broadcast reset to dashboard
    await manager.broadcast({"type":"reset","scenario":name})

    # Start engine with selected pcap
    pcap_path = SCENARIOS[name]
    engine_process = subprocess.Popen(
        [ENGINE_PATH, "--demo", pcap_path, "--bridge", "http://localhost:8000"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    return {"ok": True, "scenario": name, "pcap": pcap_path}

@app.get("/scenario/status")
def scenario_status():
    running = engine_process is not None and engine_process.poll() is None
    return {"engine_running": running}

# ─── Dashboard REST endpoints ────────────────────────────────
@app.get("/api/stats")
def get_stats():
    return {**stats, "uptime_seconds": int(time.time()-stats["start_time"]),
            "connected_clients": len(manager.active)}

@app.get("/api/events")
def get_events(limit: int = 100): return list(events)[-limit:]

@app.get("/api/alerts")
def get_alerts(limit: int = 50):  return list(alerts)[-limit:]

@app.get("/api/protocol-distribution")
def get_proto():
    total = sum(stats["protocols"].values()) or 1
    return [{"protocol":k,"count":v,"pct":round(v/total*100,1)}
            for k,v in stats["protocols"].items()]

# ─── WebSocket ───────────────────────────────────────────────
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await manager.connect(ws)
    await ws.send_json({"type":"init","data":{
        "stats": stats,
        "recent_events": list(events)[-20:],
        "recent_alerts": list(alerts)[-10:],
    }})
    try:
        while True: await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)

@app.get("/health")
def health(): return {"status":"ok"}
