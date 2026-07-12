from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import time, subprocess, os, asyncio
import aiosqlite
from collections import deque

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# In-memory cache (fast access)
events  = deque(maxlen=1000)
alerts  = deque(maxlen=200)
stats   = {"total_packets":0,"total_bytes":0,"threats_detected":0,
           "anomalies_detected":0,"protocols":{},"start_time":time.time()}

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
ENGINE_PATH = os.path.join(BASE_DIR, "../engine/build/netsentinel")
DB_PATH     = os.path.join(BASE_DIR, "netsentinel.db")
SCENARIOS   = {
    "normal":        os.path.join(BASE_DIR, "../demo/normal_traffic.pcap"),
    "port-scan":     os.path.join(BASE_DIR, "../demo/port_scan.pcap"),
    "sql-injection": os.path.join(BASE_DIR, "../demo/sql_injection.pcap"),
    "exfiltration":  os.path.join(BASE_DIR, "../demo/exfiltration.pcap"),
}

engine_process = None

# ─── Database setup ─────────────────────────────────────────
async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   REAL,
                src_ip      TEXT,
                dst_ip      TEXT,
                src_port    INTEGER,
                dst_port    INTEGER,
                protocol    TEXT,
                app_protocol TEXT,
                host        TEXT,
                bytes       INTEGER,
                verdict     TEXT,
                module      TEXT,
                reason      TEXT
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                type      TEXT,
                src_ip    TEXT,
                dst_ip    TEXT,
                host      TEXT,
                verdict   TEXT,
                reason    TEXT,
                score     REAL,
                deviations TEXT
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS stats_snapshots (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       REAL,
                total_packets   INTEGER,
                total_bytes     INTEGER,
                threats         INTEGER,
                anomalies       INTEGER
            )
        """)
        await db.commit()
    print("[db] SQLite initialized at", DB_PATH)

# ─── Load persisted stats on startup ────────────────────────
async def load_persisted_stats():
    async with aiosqlite.connect(DB_PATH) as db:
        # Load packet count + bytes
        async with db.execute("SELECT COUNT(*), SUM(bytes) FROM packets") as cur:
            row = await cur.fetchone()
            if row and row[0]:
                stats["total_packets"] = row[0]
                stats["total_bytes"]   = row[1] or 0

        # Load threat count
        async with db.execute("SELECT COUNT(*) FROM alerts WHERE type='threat'") as cur:
            row = await cur.fetchone()
            if row: stats["threats_detected"] = row[0]

        # Load anomaly count
        async with db.execute("SELECT COUNT(*) FROM alerts WHERE type='anomaly'") as cur:
            row = await cur.fetchone()
            if row: stats["anomalies_detected"] = row[0]

        # Load protocol distribution
        async with db.execute("SELECT app_protocol, COUNT(*) FROM packets GROUP BY app_protocol") as cur:
            rows = await cur.fetchall()
            for proto, count in rows:
                if proto: stats["protocols"][proto] = count

        # Load last 100 events into memory cache
        async with db.execute("SELECT * FROM packets ORDER BY id DESC LIMIT 100") as cur:
            rows = await cur.fetchall()
            cols = ["id","timestamp","src_ip","dst_ip","src_port","dst_port",
                    "protocol","app_protocol","host","bytes","verdict","module","reason"]
            for row in reversed(rows):
                events.append(dict(zip(cols, row)))

        # Load last 50 alerts into memory cache
        async with db.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 50") as cur:
            rows = await cur.fetchall()
            cols = ["id","timestamp","type","src_ip","dst_ip","host",
                    "verdict","reason","score","deviations"]
            for row in reversed(rows):
                alerts.append(dict(zip(cols, row)))

    print(f"[db] Loaded {stats['total_packets']} packets, "
          f"{stats['threats_detected']} threats, "
          f"{stats['anomalies_detected']} anomalies from DB")

@app.on_event("startup")
async def startup():
    await init_db()
    await load_persisted_stats()

# ─── WebSocket manager ───────────────────────────────────────
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

# ─── Models ──────────────────────────────────────────────────
class PacketEvent(BaseModel):
    src_ip: str; dst_ip: str; src_port: int; dst_port: int
    protocol: str; app_protocol: str = ""; host: str = ""
    bytes: int; verdict: str; module: str = ""; reason: str = ""
    timestamp: Optional[float] = None

class AnomalyEvent(BaseModel):
    ip: str; score: float; verdict: str
    deviations: list[dict]; timestamp: Optional[float] = None

# ─── Ingest endpoints ────────────────────────────────────────
@app.post("/ingest/packet")
async def ingest_packet(e: PacketEvent):
    e.timestamp = e.timestamp or time.time()
    d = e.model_dump()
    events.append(d)
    stats["total_packets"] += 1
    stats["total_bytes"]   += e.bytes
    proto = e.app_protocol or e.protocol
    stats["protocols"][proto] = stats["protocols"].get(proto, 0) + 1

    # Persist to SQLite
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO packets
            (timestamp,src_ip,dst_ip,src_port,dst_port,protocol,
             app_protocol,host,bytes,verdict,module,reason)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (e.timestamp, e.src_ip, e.dst_ip, e.src_port, e.dst_port,
              e.protocol, e.app_protocol, e.host, e.bytes,
              e.verdict, e.module, e.reason))
        await db.commit()

    if e.verdict in ("DROP","ALERT"):
        stats["threats_detected"] += 1
        alert = {**d, "type":"threat"}
        alerts.append(alert)
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("""
                INSERT INTO alerts
                (timestamp,type,src_ip,dst_ip,host,verdict,reason,score,deviations)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (e.timestamp,"threat",e.src_ip,e.dst_ip,
                  e.host,e.verdict,e.reason,0,""))
            await db.commit()

    await manager.broadcast({"type":"packet","data":d})
    return {"ok": True}

@app.post("/ingest/anomaly")
async def ingest_anomaly(e: AnomalyEvent):
    import json
    e.timestamp = e.timestamp or time.time()
    d = e.model_dump()
    stats["anomalies_detected"] += 1
    alerts.append({**d, "type":"anomaly"})

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO alerts
            (timestamp,type,src_ip,dst_ip,host,verdict,reason,score,deviations)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (e.timestamp,"anomaly",e.ip,"","",
              e.verdict,"",e.score,json.dumps(e.deviations)))
        await db.commit()

    await manager.broadcast({"type":"anomaly","data":d})
    return {"ok": True}

# ─── Scenario endpoint ───────────────────────────────────────
@app.post("/scenario/{name}")
async def run_scenario(name: str):
    global engine_process
    if name not in SCENARIOS:
        return {"error": f"Unknown scenario. Valid: {list(SCENARIOS.keys())}"}

    if engine_process and engine_process.poll() is None:
        engine_process.terminate()
        try: engine_process.wait(timeout=3)
        except: engine_process.kill()

    # Reset in-memory stats only (keep DB history)
    stats.update({"total_packets":0,"total_bytes":0,
                  "threats_detected":0,"anomalies_detected":0,
                  "protocols":{},"start_time":time.time()})
    events.clear()
    alerts.clear()

    await manager.broadcast({"type":"reset","scenario":name})

    engine_process = subprocess.Popen(
        [ENGINE_PATH, "--demo", SCENARIOS[name], "--bridge", "http://localhost:8000"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    return {"ok": True, "scenario": name}

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
def get_alerts(limit: int = 50): return list(alerts)[-limit:]

@app.get("/api/protocol-distribution")
def get_proto():
    total = sum(stats["protocols"].values()) or 1
    return [{"protocol":k,"count":v,"pct":round(v/total*100,1)}
            for k,v in stats["protocols"].items()]

@app.get("/api/history")
async def get_history(limit: int = 500):
    """Full packet history from DB — survives restarts"""
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT * FROM packets ORDER BY id DESC LIMIT ?", (limit,)
        ) as cur:
            rows = await cur.fetchall()
            cols = ["id","timestamp","src_ip","dst_ip","src_port","dst_port",
                    "protocol","app_protocol","host","bytes","verdict","module","reason"]
            return [dict(zip(cols, row)) for row in rows]

@app.delete("/api/history")
async def clear_history():
    """Clear all DB history"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM packets")
        await db.execute("DELETE FROM alerts")
        await db.commit()
    events.clear(); alerts.clear()
    stats.update({"total_packets":0,"total_bytes":0,
                  "threats_detected":0,"anomalies_detected":0,"protocols":{}})
    return {"ok": True, "message": "History cleared"}

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
def health(): return {"status":"ok","db":DB_PATH}
