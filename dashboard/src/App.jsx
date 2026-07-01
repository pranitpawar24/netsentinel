import { useState, useEffect, useRef } from "react";
import {
  LineChart, Line, AreaChart, Area, BarChart, Bar,
  PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from "recharts";
import {
  Shield, AlertTriangle, Activity, Globe,
  Wifi, Filter, Brain, Clock, ChevronRight, Circle
} from "lucide-react";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";
const WS  = API.replace("http", "ws") + "/ws";

const PROTOCOL_COLORS = {
  HTTP: "#3266ad", DNS: "#1D9E75", TLS: "#7F77DD",
  UNKNOWN: "#888780", OTHER: "#D85A30"
};

const VERDICT_COLORS = {
  ALLOW: "#639922", DROP: "#E24B4A", ALERT: "#EF9F27", LOG: "#378ADD"
};

// ─── Demo data generator (used when no WebSocket is available) ──
function generateDemoEvent() {
  const ips = ["192.168.1.10","192.168.1.42","10.0.0.5","172.16.0.3","192.168.1.99"];
  const protos = ["HTTP","DNS","TLS","UNKNOWN"];
  const verdicts = ["ALLOW","ALLOW","ALLOW","ALLOW","LOG","DROP","ALERT"];
  const hosts = ["google.com","github.com","youtube.com","suspicious-host.ru","api.stripe.com"];
  return {
    src_ip: ips[Math.floor(Math.random() * ips.length)],
    dst_ip: `8.8.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
    src_port: 1024 + Math.floor(Math.random() * 60000),
    dst_port: [80,443,53,8080][Math.floor(Math.random()*4)],
    protocol: protos[Math.floor(Math.random() * protos.length)],
    app_protocol: protos[Math.floor(Math.random() * protos.length)],
    host: hosts[Math.floor(Math.random() * hosts.length)],
    bytes: Math.floor(Math.random() * 8000) + 64,
    verdict: verdicts[Math.floor(Math.random() * verdicts.length)],
    timestamp: Date.now() / 1000,
  };
}

function generateDemoAnomaly() {
  const ips = ["192.168.1.42","10.0.0.5"];
  const verdicts = ["POSSIBLE_EXFILTRATION","PORT_SCAN","UNUSUAL_TRAFFIC_VOLUME","BEHAVIORAL_ANOMALY"];
  return {
    ip: ips[Math.floor(Math.random() * ips.length)],
    score: (3.5 + Math.random() * 4).toFixed(1),
    verdict: verdicts[Math.floor(Math.random() * verdicts.length)],
    deviations: [
      { metric: "bytes_sent", description: "820% above baseline", z_score: 4.2 },
      { metric: "active_hour", description: "3am (never seen)", z_score: 3.5 },
    ],
    timestamp: Date.now() / 1000,
  };
}

// ─── Stat Card ──────────────────────────────────────────────
function StatCard({ icon: Icon, label, value, sub, color = "#378ADD" }) {
  return (
    <div style={{
      background: "var(--color-background-primary)",
      border: "0.5px solid var(--color-border-tertiary)",
      borderRadius: "var(--border-radius-lg)",
      padding: "1rem 1.25rem",
      display: "flex", alignItems: "flex-start", gap: 12,
    }}>
      <div style={{
        width: 36, height: 36, borderRadius: "var(--border-radius-md)",
        background: color + "22",
        display: "flex", alignItems: "center", justifyContent: "center",
        flexShrink: 0,
      }}>
        <Icon size={18} color={color} />
      </div>
      <div>
        <div style={{ fontSize: 13, color: "var(--color-text-secondary)", marginBottom: 2 }}>{label}</div>
        <div style={{ fontSize: 22, fontWeight: 500 }}>{value}</div>
        {sub && <div style={{ fontSize: 12, color: "var(--color-text-tertiary)", marginTop: 2 }}>{sub}</div>}
      </div>
    </div>
  );
}

// ─── Alert Badge ─────────────────────────────────────────────
function VerdictBadge({ verdict }) {
  const color = VERDICT_COLORS[verdict] || "#888";
  return (
    <span style={{
      fontSize: 11, fontWeight: 500, padding: "2px 8px",
      borderRadius: 99, background: color + "22", color,
      border: `0.5px solid ${color}44`,
    }}>{verdict}</span>
  );
}

// ─── Main App ────────────────────────────────────────────────
export default function App() {
  const [stats, setStats] = useState({
    total_packets: 0, total_bytes: 0,
    threats_detected: 0, anomalies_detected: 0,
    protocols: {}, uptime_seconds: 0,
  });
  const [events, setEvents]   = useState([]);
  const [alerts, setAlerts]   = useState([]);
  const [traffic, setTraffic] = useState([]); // time-series for chart
  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);
  const demoRef = useRef(null);

  // Time-series: add a point every second
  const statsRef = useRef(stats);
  statsRef.current = stats;

  useEffect(() => {
    // Try real WebSocket first
    try {
      const ws = new WebSocket(WS);
      ws.onopen = () => setConnected(true);
      ws.onclose = () => { setConnected(false); startDemo(); };
      ws.onerror = () => { ws.close(); };
      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        if (msg.type === "init") {
          setStats(msg.data.stats);
          setEvents(msg.data.recent_events || []);
          setAlerts(msg.data.recent_alerts || []);
        } else if (msg.type === "packet") {
          handlePacket(msg.data);
        } else if (msg.type === "anomaly") {
          handleAnomaly(msg.data);
        }
      };
      wsRef.current = ws;
    } catch {
      startDemo();
    }

    return () => {
      wsRef.current?.close();
      clearInterval(demoRef.current);
    };
  }, []);

  // Traffic time-series
  useEffect(() => {
    const interval = setInterval(() => {
      setTraffic(prev => {
        const now = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
        const next = [...prev.slice(-29), {
          time: now,
          packets: statsRef.current.total_packets,
          threats: statsRef.current.threats_detected,
        }];
        return next;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  function startDemo() {
    // Fallback: generate synthetic events locally
    demoRef.current = setInterval(() => {
      if (Math.random() < 0.05) {
        handleAnomaly(generateDemoAnomaly());
      } else {
        handlePacket(generateDemoEvent());
      }
    }, 300);
  }

  function handlePacket(data) {
    setEvents(prev => [data, ...prev.slice(0, 99)]);
    setStats(prev => ({
      ...prev,
      total_packets: prev.total_packets + 1,
      total_bytes: prev.total_bytes + (data.bytes || 0),
      threats_detected: data.verdict === "ALERT" || data.verdict === "DROP"
        ? prev.threats_detected + 1 : prev.threats_detected,
      protocols: {
        ...prev.protocols,
        [data.app_protocol || data.protocol]:
          (prev.protocols[data.app_protocol || data.protocol] || 0) + 1,
      },
    }));
    if (data.verdict === "ALERT" || data.verdict === "DROP") {
      setAlerts(prev => [{ ...data, type: "threat" }, ...prev.slice(0, 49)]);
    }
  }

  function handleAnomaly(data) {
    setAlerts(prev => [{ ...data, type: "anomaly" }, ...prev.slice(0, 49)]);
    setStats(prev => ({ ...prev, anomalies_detected: prev.anomalies_detected + 1 }));
  }

  // Protocol pie data
  const protoPieData = Object.entries(stats.protocols).map(([name, value]) => ({
    name, value, fill: PROTOCOL_COLORS[name] || "#888"
  }));

  const formatBytes = (b) => {
    if (b > 1e9) return (b / 1e9).toFixed(1) + " GB";
    if (b > 1e6) return (b / 1e6).toFixed(1) + " MB";
    if (b > 1e3) return (b / 1e3).toFixed(1) + " KB";
    return b + " B";
  };

  const formatUptime = (s) => {
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    return `${h}h ${m}m ${sec}s`;
  };

  return (
    <div style={{ fontFamily: "var(--font-sans)", padding: "1.5rem", maxWidth: 1100, margin: "0 auto" }}>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "1.5rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Shield size={24} color="#534AB7" />
          <span style={{ fontSize: 20, fontWeight: 500 }}>NetSentinel</span>
          <span style={{
            fontSize: 11, padding: "2px 8px", borderRadius: 99,
            background: connected ? "#63992222" : "#EF9F2722",
            color: connected ? "#639922" : "#EF9F27",
            border: `0.5px solid ${connected ? "#63992244" : "#EF9F2744"}`,
            marginLeft: 4,
          }}>
            {connected ? "● Live" : "● Demo mode"}
          </span>
        </div>
        <div style={{ fontSize: 13, color: "var(--color-text-secondary)", display: "flex", alignItems: "center", gap: 6 }}>
          <Clock size={14} />
          Uptime: {formatUptime(stats.uptime_seconds)}
        </div>
      </div>

      {/* Stat cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12, marginBottom: "1.5rem" }}>
        <StatCard icon={Activity} label="Total packets" value={stats.total_packets.toLocaleString()} color="#378ADD" />
        <StatCard icon={Wifi} label="Total traffic" value={formatBytes(stats.total_bytes)} color="#1D9E75" />
        <StatCard icon={AlertTriangle} label="Threats detected" value={stats.threats_detected} color="#E24B4A" />
        <StatCard icon={Brain} label="Anomalies flagged" value={stats.anomalies_detected} color="#7F77DD" />
      </div>

      {/* Charts row */}
      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 12, marginBottom: "1.5rem" }}>

        {/* Traffic over time */}
        <div style={{
          background: "var(--color-background-primary)",
          border: "0.5px solid var(--color-border-tertiary)",
          borderRadius: "var(--border-radius-lg)",
          padding: "1rem 1.25rem",
        }}>
          <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 12 }}>Traffic over time</div>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={traffic}>
              <defs>
                <linearGradient id="pktGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#378ADD" stopOpacity={0.15} />
                  <stop offset="95%" stopColor="#378ADD" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border-tertiary)" />
              <XAxis dataKey="time" tick={{ fontSize: 10, fill: "var(--color-text-tertiary)" }} interval="preserveStartEnd" />
              <YAxis tick={{ fontSize: 10, fill: "var(--color-text-tertiary)" }} />
              <Tooltip contentStyle={{ fontSize: 12, background: "var(--color-background-primary)", border: "0.5px solid var(--color-border-tertiary)" }} />
              <Area type="monotone" dataKey="packets" stroke="#378ADD" fill="url(#pktGrad)" strokeWidth={1.5} dot={false} name="Packets" />
              <Area type="monotone" dataKey="threats" stroke="#E24B4A" fill="none" strokeWidth={1.5} strokeDasharray="4 2" dot={false} name="Threats" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Protocol distribution */}
        <div style={{
          background: "var(--color-background-primary)",
          border: "0.5px solid var(--color-border-tertiary)",
          borderRadius: "var(--border-radius-lg)",
          padding: "1rem 1.25rem",
        }}>
          <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 12 }}>Protocol distribution</div>
          {protoPieData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={140}>
                <PieChart>
                  <Pie data={protoPieData} dataKey="value" cx="50%" cy="50%" outerRadius={60} strokeWidth={0}>
                    {protoPieData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ fontSize: 12, background: "var(--color-background-primary)", border: "0.5px solid var(--color-border-tertiary)" }} />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 8 }}>
                {protoPieData.map((d, i) => (
                  <span key={i} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 11, color: "var(--color-text-secondary)" }}>
                    <span style={{ width: 8, height: 8, borderRadius: 2, background: d.fill, display: "inline-block" }} />
                    {d.name}
                  </span>
                ))}
              </div>
            </>
          ) : (
            <div style={{ fontSize: 13, color: "var(--color-text-tertiary)", textAlign: "center", marginTop: 40 }}>
              Waiting for traffic…
            </div>
          )}
        </div>
      </div>

      {/* Bottom row: alerts + live feed */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>

        {/* Alerts panel */}
        <div style={{
          background: "var(--color-background-primary)",
          border: "0.5px solid var(--color-border-tertiary)",
          borderRadius: "var(--border-radius-lg)",
          padding: "1rem 1.25rem",
        }}>
          <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 12, display: "flex", alignItems: "center", gap: 6 }}>
            <AlertTriangle size={14} color="#E24B4A" />
            Alerts &amp; anomalies
          </div>
          <div style={{ maxHeight: 320, overflowY: "auto" }}>
            {alerts.length === 0 && (
              <div style={{ fontSize: 13, color: "var(--color-text-tertiary)", padding: "2rem 0", textAlign: "center" }}>
                No alerts yet
              </div>
            )}
            {alerts.map((a, i) => (
              <div key={i} style={{
                padding: "10px 0",
                borderBottom: "0.5px solid var(--color-border-tertiary)",
                display: "flex", alignItems: "flex-start", gap: 10,
              }}>
                {a.type === "anomaly" ? (
                  <Brain size={14} color="#7F77DD" style={{ marginTop: 2, flexShrink: 0 }} />
                ) : (
                  <AlertTriangle size={14} color="#E24B4A" style={{ marginTop: 2, flexShrink: 0 }} />
                )}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 12, fontWeight: 500, marginBottom: 2 }}>
                    {a.type === "anomaly"
                      ? `${a.verdict} — ${a.ip}`
                      : `${a.verdict} — ${a.src_ip} → ${a.host || a.dst_ip}`}
                  </div>
                  {a.type === "anomaly" && (
                    <div style={{ fontSize: 11, color: "var(--color-text-secondary)" }}>
                      Score: {parseFloat(a.score).toFixed(1)} · {a.deviations?.[0]?.description}
                    </div>
                  )}
                  {a.type === "threat" && a.reason && (
                    <div style={{ fontSize: 11, color: "var(--color-text-secondary)" }}>{a.reason}</div>
                  )}
                </div>
                {a.type === "anomaly" && (
                  <span style={{
                    fontSize: 11, padding: "1px 6px", borderRadius: 99,
                    background: "#7F77DD22", color: "#7F77DD",
                  }}>anomaly</span>
                )}
                {a.type === "threat" && <VerdictBadge verdict={a.verdict} />}
              </div>
            ))}
          </div>
        </div>

        {/* Live packet feed */}
        <div style={{
          background: "var(--color-background-primary)",
          border: "0.5px solid var(--color-border-tertiary)",
          borderRadius: "var(--border-radius-lg)",
          padding: "1rem 1.25rem",
        }}>
          <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 12, display: "flex", alignItems: "center", gap: 6 }}>
            <Globe size={14} color="#378ADD" />
            Live packet feed
          </div>
          <div style={{ maxHeight: 320, overflowY: "auto", fontFamily: "var(--font-mono)", fontSize: 11 }}>
            {events.slice(0, 50).map((e, i) => (
              <div key={i} style={{
                display: "flex", alignItems: "center", gap: 8,
                padding: "5px 0",
                borderBottom: "0.5px solid var(--color-border-tertiary)",
                color: "var(--color-text-secondary)",
              }}>
                <Circle size={6} fill={VERDICT_COLORS[e.verdict] || "#888"} color="transparent" style={{ flexShrink: 0 }} />
                <span style={{ color: "var(--color-text-primary)", minWidth: 100 }}>{e.src_ip}</span>
                <ChevronRight size={10} style={{ flexShrink: 0 }} />
                <span style={{ minWidth: 100 }}>{e.host || e.dst_ip}</span>
                <span style={{
                  padding: "1px 5px", borderRadius: 4,
                  background: (PROTOCOL_COLORS[e.app_protocol || e.protocol] || "#888") + "22",
                  color: PROTOCOL_COLORS[e.app_protocol || e.protocol] || "#888",
                }}>{e.app_protocol || e.protocol}</span>
                <span style={{ marginLeft: "auto" }}>{e.bytes}B</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Footer */}
      <div style={{ marginTop: "1.5rem", fontSize: 12, color: "var(--color-text-tertiary)", textAlign: "center" }}>
        NetSentinel · Deep Packet Inspection Engine · Demo mode uses synthetic traffic
      </div>
    </div>
  );
}
