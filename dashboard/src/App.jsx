import { useState, useEffect, useRef } from "react";
import { AreaChart, Area, PieChart, Pie, Cell,
         XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { Shield, AlertTriangle, Activity, Globe,
         Wifi, Brain, Clock, ChevronRight, Circle, Play } from "lucide-react";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";
const WS  = API.replace("http", "ws") + "/ws";

const PROTOCOL_COLORS = {
  HTTP:"#3266ad", DNS:"#1D9E75", TLS:"#7F77DD", UNKNOWN:"#888780", TCP:"#D85A30", UDP:"#E8A838"
};
const VERDICT_COLORS = {
  ALLOW:"#639922", DROP:"#E24B4A", ALERT:"#EF9F27", LOG:"#378ADD"
};
const SCENARIOS = [
  { id:"normal",        label:"🌐 Normal Traffic",    color:"#1D9E75", desc:"HTTP, DNS, TLS browsing" },
  { id:"port-scan",     label:"🔍 Port Scan Attack",  color:"#EF9F27", desc:"Nmap SYN scan on 30 ports" },
  { id:"sql-injection", label:"💉 SQL Injection",     color:"#E24B4A", desc:"SQLi + XSS payloads over HTTP" },
  { id:"exfiltration",  label:"📤 Data Exfiltration", color:"#7F77DD", desc:"Large upload to foreign IP at odd port" },
];

function StatCard({ icon: Icon, label, value, color="#378ADD" }) {
  return (
    <div style={{ background:"var(--color-background-primary)",
      border:"0.5px solid var(--color-border-tertiary)",
      borderRadius:"var(--border-radius-lg)", padding:"1rem 1.25rem",
      display:"flex", alignItems:"flex-start", gap:12 }}>
      <div style={{ width:36, height:36, borderRadius:"var(--border-radius-md)",
        background:color+"22", display:"flex", alignItems:"center",
        justifyContent:"center", flexShrink:0 }}>
        <Icon size={18} color={color} />
      </div>
      <div>
        <div style={{ fontSize:13, color:"var(--color-text-secondary)", marginBottom:2 }}>{label}</div>
        <div style={{ fontSize:22, fontWeight:500 }}>{value}</div>
      </div>
    </div>
  );
}

function VerdictBadge({ verdict }) {
  const color = VERDICT_COLORS[verdict] || "#888";
  return (
    <span style={{ fontSize:11, fontWeight:500, padding:"2px 8px", borderRadius:99,
      background:color+"22", color, border:`0.5px solid ${color}44` }}>{verdict}</span>
  );
}

// Demo data generator (fallback when no engine running)
function generateDemoEvent() {
  const ips = ["192.168.1.10","192.168.1.42","10.0.0.5","172.16.0.3"];
  const protos = ["HTTP","DNS","TLS","UNKNOWN"];
  const verdicts = ["ALLOW","ALLOW","ALLOW","LOG","DROP","ALERT"];
  const hosts = ["google.com","github.com","youtube.com","suspicious-host.ru","api.stripe.com"];
  return {
    src_ip: ips[Math.floor(Math.random()*ips.length)],
    dst_ip: `8.8.${Math.floor(Math.random()*255)}.1`,
    src_port: 1024+Math.floor(Math.random()*60000),
    dst_port: [80,443,53,8080][Math.floor(Math.random()*4)],
    protocol: "TCP", app_protocol: protos[Math.floor(Math.random()*protos.length)],
    host: hosts[Math.floor(Math.random()*hosts.length)],
    bytes: Math.floor(Math.random()*8000)+64,
    verdict: verdicts[Math.floor(Math.random()*verdicts.length)],
    timestamp: Date.now()/1000,
  };
}

export default function App() {
  const [stats, setStats]           = useState({ total_packets:0, total_bytes:0, threats_detected:0, anomalies_detected:0, protocols:{}, uptime_seconds:0 });
  const [events, setEvents]         = useState([]);
  const [alerts, setAlerts]         = useState([]);
  const [traffic, setTraffic]       = useState([]);
  const [connected, setConnected]   = useState(false);
  const [activeScene, setActiveScene] = useState(null);
  const [sceneLoading, setSceneLoading] = useState(false);
  const wsRef   = useRef(null);
  const demoRef = useRef(null);
  const statsRef = useRef(stats);
  statsRef.current = stats;

  useEffect(() => {
    tryConnect();
    const interval = setInterval(() => {
      setTraffic(prev => {
        const now = new Date().toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"});
        return [...prev.slice(-29), { time:now, packets:statsRef.current.total_packets, threats:statsRef.current.threats_detected }];
      });
    }, 1000);
    return () => { wsRef.current?.close(); clearInterval(demoRef.current); clearInterval(interval); };
  }, []);

  function tryConnect() {
    try {
      const ws = new WebSocket(WS);
      ws.onopen  = () => { setConnected(true); clearInterval(demoRef.current); };
      ws.onclose = () => { setConnected(false); startDemo(); };
      ws.onerror = () => ws.close();
      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        if (msg.type === "init")    { setStats(msg.data.stats); setEvents(msg.data.recent_events||[]); setAlerts(msg.data.recent_alerts||[]); }
        if (msg.type === "packet")  handlePacket(msg.data);
        if (msg.type === "anomaly") handleAnomaly(msg.data);
        if (msg.type === "reset")   { setEvents([]); setAlerts([]); setTraffic([]); setStats({ total_packets:0,total_bytes:0,threats_detected:0,anomalies_detected:0,protocols:{},uptime_seconds:0 }); }
      };
      wsRef.current = ws;
    } catch { startDemo(); }
  }

  function startDemo() {
    clearInterval(demoRef.current);
    demoRef.current = setInterval(() => handlePacket(generateDemoEvent()), 300);
  }

  function handlePacket(data) {
    setEvents(prev => [data, ...prev.slice(0,99)]);
    setStats(prev => ({
      ...prev, total_packets: prev.total_packets+1, total_bytes: prev.total_bytes+(data.bytes||0),
      threats_detected: (data.verdict==="ALERT"||data.verdict==="DROP") ? prev.threats_detected+1 : prev.threats_detected,
      protocols: { ...prev.protocols, [data.app_protocol||data.protocol]: (prev.protocols[data.app_protocol||data.protocol]||0)+1 },
    }));
    if (data.verdict==="ALERT"||data.verdict==="DROP")
      setAlerts(prev => [{...data,type:"threat"}, ...prev.slice(0,49)]);
  }

  function handleAnomaly(data) {
    setAlerts(prev => [{...data,type:"anomaly"}, ...prev.slice(0,49)]);
    setStats(prev => ({...prev, anomalies_detected: prev.anomalies_detected+1}));
  }

  async function runScenario(id) {
    setSceneLoading(true);
    setActiveScene(id);
    try {
      await fetch(`${API}/scenario/${id}`, { method:"POST" });
    } catch(e) {
      console.error("Scenario error:", e);
    }
    setSceneLoading(false);
  }

  const protoPieData = Object.entries(stats.protocols).map(([name,value]) => ({
    name, value, fill: PROTOCOL_COLORS[name]||"#888"
  }));

  const formatBytes = b => b>1e9?(b/1e9).toFixed(1)+" GB":b>1e6?(b/1e6).toFixed(1)+" MB":b>1e3?(b/1e3).toFixed(1)+" KB":b+" B";
  const formatUptime = s => `${Math.floor(s/3600)}h ${Math.floor((s%3600)/60)}m ${s%60}s`;

  return (
    <div style={{ fontFamily:"var(--font-sans)", padding:"1.5rem", maxWidth:1100, margin:"0 auto" }}>

      {/* Header */}
      <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:"1.25rem" }}>
        <div style={{ display:"flex", alignItems:"center", gap:10 }}>
          <Shield size={22} color="#534AB7" />
          <span style={{ fontSize:18, fontWeight:500 }}>NetSentinel</span>
          <span style={{ fontSize:11, padding:"2px 8px", borderRadius:99,
            background: connected?"#63992222":"#EF9F2722",
            color: connected?"#639922":"#EF9F27",
            border:`0.5px solid ${connected?"#63992244":"#EF9F2744"}` }}>
            {connected ? "● Live" : "● Demo mode"}
          </span>
        </div>
        <div style={{ fontSize:12, color:"var(--color-text-secondary)", display:"flex", alignItems:"center", gap:5 }}>
          <Clock size={13}/> {formatUptime(stats.uptime_seconds)}
        </div>
      </div>

      {/* Scenario Selector */}
      <div style={{ background:"var(--color-background-primary)",
        border:"0.5px solid var(--color-border-tertiary)",
        borderRadius:"var(--border-radius-lg)", padding:"1rem 1.25rem", marginBottom:"1.25rem" }}>
        <div style={{ fontSize:12, fontWeight:500, marginBottom:10, color:"var(--color-text-secondary)", display:"flex", alignItems:"center", gap:6 }}>
          <Play size={13}/> SELECT ATTACK SCENARIO
        </div>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:10 }}>
          {SCENARIOS.map(s => (
            <button key={s.id} onClick={() => runScenario(s.id)}
              disabled={sceneLoading}
              style={{ padding:"10px 12px", borderRadius:"var(--border-radius-md)",
                border:`1px solid ${activeScene===s.id ? s.color : "var(--color-border-tertiary)"}`,
                background: activeScene===s.id ? s.color+"22" : "var(--color-background-secondary)",
                color: activeScene===s.id ? s.color : "var(--color-text-primary)",
                cursor: sceneLoading?"wait":"pointer", textAlign:"left",
                transition:"all 0.15s", opacity: sceneLoading?0.7:1 }}>
              <div style={{ fontSize:13, fontWeight:500, marginBottom:3 }}>{s.label}</div>
              <div style={{ fontSize:11, color:"var(--color-text-tertiary)" }}>{s.desc}</div>
            </button>
          ))}
        </div>
        {activeScene && (
          <div style={{ marginTop:10, fontSize:12, color:"var(--color-text-secondary)" }}>
            {sceneLoading ? "⏳ Starting scenario..." : `▶ Running: ${SCENARIOS.find(s=>s.id===activeScene)?.label}`}
          </div>
        )}
      </div>

      {/* Stat Cards */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:12, marginBottom:"1.25rem" }}>
        <StatCard icon={Activity} label="Total packets"    value={stats.total_packets.toLocaleString()} color="#378ADD"/>
        <StatCard icon={Wifi}     label="Total traffic"    value={formatBytes(stats.total_bytes)}        color="#1D9E75"/>
        <StatCard icon={AlertTriangle} label="Threats"     value={stats.threats_detected}               color="#E24B4A"/>
        <StatCard icon={Brain}    label="Anomalies flagged" value={stats.anomalies_detected}             color="#7F77DD"/>
      </div>

      {/* Charts Row */}
      <div style={{ display:"grid", gridTemplateColumns:"2fr 1fr", gap:12, marginBottom:"1.25rem" }}>
        <div style={{ background:"var(--color-background-primary)", border:"0.5px solid var(--color-border-tertiary)", borderRadius:"var(--border-radius-lg)", padding:"1rem 1.25rem" }}>
          <div style={{ fontSize:13, fontWeight:500, marginBottom:12 }}>Traffic over time</div>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={traffic}>
              <defs>
                <linearGradient id="ag" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#378ADD" stopOpacity={0.15}/>
                  <stop offset="95%" stopColor="#378ADD" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border-tertiary)"/>
              <XAxis dataKey="time" tick={{fontSize:10,fill:"var(--color-text-tertiary)"}} interval="preserveStartEnd"/>
              <YAxis tick={{fontSize:10,fill:"var(--color-text-tertiary)"}}/>
              <Tooltip contentStyle={{fontSize:12,background:"var(--color-background-primary)",border:"0.5px solid var(--color-border-tertiary)"}}/>
              <Area type="monotone" dataKey="packets" stroke="#378ADD" fill="url(#ag)" strokeWidth={1.5} dot={false} name="Packets"/>
              <Area type="monotone" dataKey="threats" stroke="#E24B4A" fill="none" strokeWidth={1.5} strokeDasharray="4 2" dot={false} name="Threats"/>
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div style={{ background:"var(--color-background-primary)", border:"0.5px solid var(--color-border-tertiary)", borderRadius:"var(--border-radius-lg)", padding:"1rem 1.25rem" }}>
          <div style={{ fontSize:13, fontWeight:500, marginBottom:12 }}>Protocol distribution</div>
          {protoPieData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={140}>
                <PieChart>
                  <Pie data={protoPieData} dataKey="value" cx="50%" cy="50%" outerRadius={60} strokeWidth={0}>
                    {protoPieData.map((e,i) => <Cell key={i} fill={e.fill}/>)}
                  </Pie>
                  <Tooltip contentStyle={{fontSize:12,background:"var(--color-background-primary)",border:"0.5px solid var(--color-border-tertiary)"}}/>
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display:"flex", flexWrap:"wrap", gap:8, marginTop:8 }}>
                {protoPieData.map((d,i) => (
                  <span key={i} style={{ display:"flex", alignItems:"center", gap:4, fontSize:11, color:"var(--color-text-secondary)" }}>
                    <span style={{ width:8, height:8, borderRadius:2, background:d.fill, display:"inline-block"}}/>
                    {d.name}
                  </span>
                ))}
              </div>
            </>
          ) : (
            <div style={{ fontSize:13, color:"var(--color-text-tertiary)", textAlign:"center", marginTop:40 }}>
              Click a scenario to start
            </div>
          )}
        </div>
      </div>

      {/* Bottom Row */}
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
        {/* Alerts */}
        <div style={{ background:"var(--color-background-primary)", border:"0.5px solid var(--color-border-tertiary)", borderRadius:"var(--border-radius-lg)", padding:"1rem 1.25rem" }}>
          <div style={{ fontSize:13, fontWeight:500, marginBottom:12, display:"flex", alignItems:"center", gap:6 }}>
            <AlertTriangle size={14} color="#E24B4A"/> Alerts &amp; anomalies
          </div>
          <div style={{ maxHeight:280, overflowY:"auto" }}>
            {alerts.length === 0 && (
              <div style={{ fontSize:13, color:"var(--color-text-tertiary)", padding:"2rem 0", textAlign:"center" }}>
                No alerts yet — run a scenario
              </div>
            )}
            {alerts.map((a,i) => (
              <div key={i} style={{ padding:"9px 0", borderBottom:"0.5px solid var(--color-border-tertiary)", display:"flex", alignItems:"flex-start", gap:10 }}>
                {a.type==="anomaly"
                  ? <Brain size={13} color="#7F77DD" style={{marginTop:2,flexShrink:0}}/>
                  : <AlertTriangle size={13} color="#E24B4A" style={{marginTop:2,flexShrink:0}}/>}
                <div style={{ flex:1, minWidth:0 }}>
                  <div style={{ fontSize:12, fontWeight:500, marginBottom:2 }}>
                    {a.type==="anomaly"
                      ? `${a.verdict} — ${a.ip}`
                      : `${a.verdict} — ${a.src_ip} → ${a.host||a.dst_ip}`}
                  </div>
                  {a.type==="anomaly" && (
                    <div style={{ fontSize:11, color:"var(--color-text-secondary)" }}>
                      Score: {parseFloat(a.score).toFixed(1)} · {a.deviations?.[0]?.description}
                    </div>
                  )}
                  {a.type==="threat" && a.reason && (
                    <div style={{ fontSize:11, color:"var(--color-text-secondary)" }}>{a.reason}</div>
                  )}
                </div>
                {a.type==="anomaly"
                  ? <span style={{ fontSize:11, padding:"1px 6px", borderRadius:99, background:"#7F77DD22", color:"#7F77DD" }}>anomaly</span>
                  : <VerdictBadge verdict={a.verdict}/>}
              </div>
            ))}
          </div>
        </div>

        {/* Live Feed */}
        <div style={{ background:"var(--color-background-primary)", border:"0.5px solid var(--color-border-tertiary)", borderRadius:"var(--border-radius-lg)", padding:"1rem 1.25rem" }}>
          <div style={{ fontSize:13, fontWeight:500, marginBottom:12, display:"flex", alignItems:"center", gap:6 }}>
            <Globe size={14} color="#378ADD"/> Live packet feed
          </div>
          <div style={{ maxHeight:280, overflowY:"auto", fontFamily:"var(--font-mono)", fontSize:11 }}>
            {events.length === 0 && (
              <div style={{ fontSize:13, color:"var(--color-text-tertiary)", padding:"2rem 0", textAlign:"center" }}>
                Click a scenario above to start
              </div>
            )}
            {events.slice(0,60).map((e,i) => (
              <div key={i} style={{ display:"flex", alignItems:"center", gap:8, padding:"4px 0",
                borderBottom:"0.5px solid var(--color-border-tertiary)", color:"var(--color-text-secondary)" }}>
                <Circle size={6} fill={VERDICT_COLORS[e.verdict]||"#888"} color="transparent" style={{flexShrink:0}}/>
                <span style={{ color:"var(--color-text-primary)", minWidth:95 }}>{e.src_ip}</span>
                <ChevronRight size={10} style={{flexShrink:0}}/>
                <span style={{ flex:1, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{e.host||e.dst_ip}</span>
                <span style={{ padding:"1px 5px", borderRadius:4,
                  background:(PROTOCOL_COLORS[e.app_protocol||e.protocol]||"#888")+"22",
                  color:PROTOCOL_COLORS[e.app_protocol||e.protocol]||"#888", flexShrink:0 }}>
                  {e.app_protocol||e.protocol}
                </span>
                <span style={{ marginLeft:"auto", flexShrink:0 }}>{e.bytes}B</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div style={{ marginTop:"1.5rem", fontSize:12, color:"var(--color-text-tertiary)", textAlign:"center" }}>
        NetSentinel · Deep Packet Inspection Engine · <a href="https://github.com/pranitpawar24/netsentinel" style={{color:"var(--color-text-tertiary)"}}>GitHub</a>
      </div>
    </div>
  );
}
