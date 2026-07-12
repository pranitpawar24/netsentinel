import { useState, useEffect, useRef, useCallback } from "react";
import {
  AreaChart, Area, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from "recharts";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";
const WS  = API.replace("http", "ws") + "/ws";

const THEMES = {
  dark: {
    bg:"#0D1117", bgSecond:"#161B22", bgThird:"#1C2128",
    border:"#30363D", borderSub:"#21262D",
    text:"#E6EDF3", textSub:"#8B949E", textMuted:"#484F58",
    teal:"#00D4AA", red:"#FF4560", amber:"#FFB020",
    violet:"#A78BFA", blue:"#58A6FF", green:"#3FB950",
  },
  light: {
    bg:"#FFFFFF", bgSecond:"#F6F8FA", bgThird:"#EAEEF2",
    border:"#D0D7DE", borderSub:"#E8ECF0",
    text:"#1F2328", textSub:"#57606A", textMuted:"#8C959F",
    teal:"#0DA68A", red:"#CF222E", amber:"#9A6700",
    violet:"#7C3AED", blue:"#0550AE", green:"#1A7F37",
  },
};

const PROTOCOL_COLORS = ["#00D4AA","#58A6FF","#A78BFA","#FFB020","#FF4560","#3FB950"];

const SCENARIOS = [
  { id:"normal",        label:"Normal Traffic",  color:"#3FB950", desc:"HTTP · DNS · TLS" },
  { id:"port-scan",     label:"Port Scan",        color:"#FFB020", desc:"SYN scan · 30 ports" },
  { id:"sql-injection", label:"SQL Injection",    color:"#FF4560", desc:"SQLi + XSS over HTTP" },
  { id:"exfiltration",  label:"Exfiltration",     color:"#A78BFA", desc:"Data to foreign IP" },
];

// ─── SVG Icons ───────────────────────────────────────────────
const Icon = ({ d, size=16, color="currentColor", strokeWidth=1.5, fill="none" }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill={fill}
    stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
    {Array.isArray(d) ? d.map((p,i)=><path key={i} d={p}/>) : <path d={d}/>}
  </svg>
);

const Icons = {
  shield:     "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
  activity:   "M22 12h-4l-3 9L9 3l-3 9H2",
  wifi:       ["M5 12.55a11 11 0 0 1 14.08 0","M1.42 9a16 16 0 0 1 21.16 0","M8.53 16.11a6 6 0 0 1 6.95 0","M12 20h.01"],
  alert:      ["M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z","M12 9v4","M12 17h.01"],
  brain:      ["M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.44 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2Z","M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.44 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2Z"],
  globe:      ["M12 2a10 10 0 1 0 0 20A10 10 0 0 0 12 2z","M2 12h20","M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"],
  clock:      ["M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z","M12 6v6l4 2"],
  play:       "M5 3l14 9-14 9V3z",
  sun:        ["M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10z","M12 1v2","M12 21v2","M4.22 4.22l1.42 1.42","M18.36 18.36l1.42 1.42","M1 12h2","M21 12h2","M4.22 19.78l1.42-1.42","M18.36 5.64l1.42-1.42"],
  moon:       "M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z",
  package:    ["M12.89 1.45l8 4A2 2 0 0 1 22 7.24v9.53a2 2 0 0 1-1.11 1.79l-8 4a2 2 0 0 1-1.79 0l-8-4A2 2 0 0 1 2 16.76V7.24a2 2 0 0 1 1.11-1.79l8-4a2 2 0 0 1 1.78 0z","M2.32 6.16L12 11l9.68-4.84","M12 22.08V11"],
  radio:      ["M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z","M19 10v2a7 7 0 0 1-14 0v-2","M12 19v4","M8 23h8"],
  slash:      ["M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z","M4.93 4.93l14.14 14.14"],
  chevronR:   "M9 18l6-6-6-6",
  circle:     "M12 12m-4 0a4 4 0 1 0 8 0a4 4 0 1 0-8 0",
  scan:       ["M3 7V5a2 2 0 0 1 2-2h2","M17 3h2a2 2 0 0 1 2 2v2","M21 17v2a2 2 0 0 1-2 2h-2","M7 21H5a2 2 0 0 1-2-2v-2","M7 12h10"],
  inject:     ["M14.5 2.5c0 1.5-2.5 5-2.5 5s-2.5-3.5-2.5-5a2.5 2.5 0 0 1 5 0z","M12 7.5V22","M9 15l3 3 3-3"],
  upload:     ["M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4","M17 8l-5-5-5 5","M12 3v12"],
  check:      ["M22 11.08V12a10 10 0 1 1-5.93-9.14","M22 4L12 14.01l-3-3"],
};

// Scenario-specific icons
const ScenarioIcons = {
  "normal":        <Icon d={Icons.globe} size={15}/>,
  "port-scan":     <Icon d={Icons.scan} size={15}/>,
  "sql-injection": <Icon d={Icons.inject} size={15}/>,
  "exfiltration":  <Icon d={Icons.upload} size={15}/>,
};

function generateDemoEvent() {
  const ips    = ["192.168.1.10","192.168.1.42","10.0.0.5","172.16.0.3"];
  const protos = ["HTTP","DNS","TLS","UNKNOWN"];
  const hosts  = ["google.com","github.com","youtube.com","suspicious.ru","api.stripe.com"];
  const verdicts = ["ALLOW","ALLOW","ALLOW","LOG","DROP","ALERT"];
  return {
    src_ip: ips[Math.floor(Math.random()*ips.length)],
    dst_ip: `8.8.${Math.floor(Math.random()*255)}.1`,
    src_port: 1024+Math.floor(Math.random()*60000),
    dst_port: [80,443,53,8080,4444][Math.floor(Math.random()*5)],
    protocol:"TCP", app_protocol: protos[Math.floor(Math.random()*protos.length)],
    host: hosts[Math.floor(Math.random()*hosts.length)],
    bytes: Math.floor(Math.random()*8000)+64,
    verdict: verdicts[Math.floor(Math.random()*verdicts.length)],
    timestamp: Date.now()/1000,
  };
}

function useTheme() {
  const [mode, setMode] = useState(() => {
    try { return localStorage.getItem("ns-theme") || "dark"; } catch { return "dark"; }
  });
  const toggle = useCallback(() => {
    setMode(m => { const n = m==="dark"?"light":"dark"; try{localStorage.setItem("ns-theme",n);}catch{} return n; });
  }, []);
  return [THEMES[mode], mode, toggle];
}

// ─── Components ──────────────────────────────────────────────
function LiveBadge({ connected, t }) {
  return (
    <span role="status" aria-live="polite" style={{
      display:"inline-flex", alignItems:"center", gap:6, fontSize:11,
      padding:"3px 10px", borderRadius:99, fontFamily:"'JetBrains Mono',monospace",
      background: connected?t.teal+"18":t.amber+"18",
      color: connected?t.teal:t.amber,
      border:`1px solid ${connected?t.teal+"44":t.amber+"44"}`,
    }}>
      <span style={{
        width:6, height:6, borderRadius:"50%",
        background: connected?t.teal:t.amber,
        display:"inline-block",
        boxShadow: connected?`0 0 0 3px ${t.teal}33`:"none",
        animation: connected?"pulse 2s infinite":"none",
      }}/>
      {connected ? "LIVE" : "DEMO"}
    </span>
  );
}

function StatCard({ label, value, iconPath, iconPaths, color, t }) {
  return (
    <div role="region" aria-label={label} style={{
      background:t.bgSecond, border:`1px solid ${t.border}`,
      borderRadius:12, padding:"1.1rem 1.25rem",
      display:"flex", alignItems:"center", gap:14,
      transition:"box-shadow 0.2s, border-color 0.2s",
      cursor:"default",
    }}
    onMouseEnter={e=>{e.currentTarget.style.boxShadow=`0 0 0 1px ${color}55`;e.currentTarget.style.borderColor=color+"44";}}
    onMouseLeave={e=>{e.currentTarget.style.boxShadow="none";e.currentTarget.style.borderColor=t.border;}}
    >
      <div style={{ width:40, height:40, borderRadius:10, background:color+"15",
        display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0 }}>
        <Icon d={iconPaths||iconPath} size={18} color={color} strokeWidth={1.5}/>
      </div>
      <div>
        <div style={{ fontSize:11, color:t.textSub, marginBottom:4,
          letterSpacing:"0.05em", textTransform:"uppercase",
          fontFamily:"'JetBrains Mono',monospace" }}>{label}</div>
        <div style={{ fontSize:22, fontWeight:600, color:t.text,
          fontFamily:"'JetBrains Mono',monospace", letterSpacing:"-0.02em" }}>
          {value}
        </div>
      </div>
    </div>
  );
}

function ScenarioButton({ s, active, loading, onClick, t }) {
  const isActive = active===s.id;
  return (
    <button onClick={()=>onClick(s.id)} disabled={loading}
      aria-pressed={isActive} aria-label={`Run ${s.label} scenario`}
      style={{
        padding:"12px 14px", borderRadius:10,
        border:`1px solid ${isActive?s.color:t.border}`,
        background: isActive?s.color+"15":t.bgSecond,
        color: isActive?s.color:t.text,
        cursor:loading?"wait":"pointer", textAlign:"left",
        transition:"all 0.15s ease", outline:"none",
        boxShadow: isActive?`0 0 14px ${s.color}30`:"none",
      }}
      onFocus={e=>{if(!isActive)e.currentTarget.style.outline=`2px solid ${s.color}88`;}}
      onBlur={e=>{e.currentTarget.style.outline="none";}}
      onMouseEnter={e=>{if(!isActive){e.currentTarget.style.borderColor=s.color+"66";e.currentTarget.style.background=s.color+"08";}}}
      onMouseLeave={e=>{if(!isActive){e.currentTarget.style.borderColor=t.border;e.currentTarget.style.background=t.bgSecond;}}}
    >
      <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:4 }}>
        <span style={{ color:isActive?s.color:t.textSub }}>
          {ScenarioIcons[s.id]}
        </span>
        <span style={{ fontSize:13, fontWeight:600 }}>{s.label}</span>
        {isActive && (
          <span style={{ marginLeft:"auto", fontSize:9, padding:"2px 6px", borderRadius:99,
            background:s.color+"25", color:s.color,
            fontFamily:"'JetBrains Mono',monospace", letterSpacing:"0.05em" }}>
            {loading?"STARTING":"RUNNING"}
          </span>
        )}
      </div>
      <div style={{ fontSize:11, color:t.textMuted,
        fontFamily:"'JetBrains Mono',monospace" }}>{s.desc}</div>
    </button>
  );
}

function AlertRow({ a, t }) {
  const isAnomaly = a.type==="anomaly";
  const color = isAnomaly?t.violet:(a.verdict==="DROP"?t.red:t.amber);
  const iconPath = isAnomaly?Icons.brain:Icons.alert;
  const iconPaths = isAnomaly?Icons.brain:undefined;
  return (
    <div role="listitem" style={{ display:"flex", alignItems:"flex-start", gap:10,
      padding:"9px 0", borderBottom:`1px solid ${t.borderSub}` }}>
      <div style={{ width:28, height:28, borderRadius:7, background:color+"15",
        display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0, marginTop:1 }}>
        <Icon d={Array.isArray(iconPaths)?iconPaths:iconPath} size={13} color={color} strokeWidth={1.5}/>
      </div>
      <div style={{ flex:1, minWidth:0 }}>
        <div style={{ fontSize:12, fontWeight:600, color:t.text, marginBottom:2,
          overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
          {isAnomaly?`${a.verdict} · ${a.ip}`:`${a.verdict} · ${a.src_ip} → ${a.host||a.dst_ip}`}
        </div>
        <div style={{ fontSize:11, color:t.textSub, fontFamily:"'JetBrains Mono',monospace" }}>
          {isAnomaly
            ?`score ${parseFloat(a.score).toFixed(1)} · ${a.deviations?.[0]?.description||""}`
            :a.reason||`port ${a.dst_port}`}
        </div>
      </div>
      <span style={{ fontSize:9, padding:"2px 7px", borderRadius:99,
        background:color+"18", color, border:`1px solid ${color}33`,
        fontFamily:"'JetBrains Mono',monospace", flexShrink:0, marginTop:2,
        letterSpacing:"0.05em" }}>
        {isAnomaly?"ANOMALY":a.verdict}
      </span>
    </div>
  );
}

function PacketRow({ e, t }) {
  const VCOL = { ALLOW:t.green, DROP:t.red, ALERT:t.amber, LOG:t.blue };
  const PCOL = { HTTP:t.blue, DNS:t.teal, TLS:t.violet, UNKNOWN:t.textMuted };
  const proto = e.app_protocol||e.protocol;
  return (
    <div style={{ display:"grid", gridTemplateColumns:"8px 1fr 1fr auto auto",
      alignItems:"center", gap:8, padding:"4px 0",
      borderBottom:`1px solid ${t.borderSub}`,
      fontFamily:"'JetBrains Mono',monospace", fontSize:11, color:t.textSub }}>
      <div style={{ width:6, height:6, borderRadius:"50%",
        background:VCOL[e.verdict]||t.textMuted, flexShrink:0 }}/>
      <span style={{ color:t.text, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{e.src_ip}</span>
      <span style={{ overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap", color:t.textSub }}>{e.host||e.dst_ip}</span>
      <span style={{ padding:"1px 5px", borderRadius:4, fontSize:10,
        background:(PCOL[proto]||t.textMuted)+"18", color:PCOL[proto]||t.textMuted }}>{proto}</span>
      <span style={{ color:t.textMuted, textAlign:"right" }}>
        {e.bytes>1000?(e.bytes/1000).toFixed(1)+"k":e.bytes}B
      </span>
    </div>
  );
}

// ─── Main ────────────────────────────────────────────────────
export default function App() {
  const [t, mode, toggleTheme] = useTheme();
  const [stats, setStats]         = useState({ total_packets:0,total_bytes:0,threats_detected:0,anomalies_detected:0,protocols:{},uptime_seconds:0 });
  const [events, setEvents]       = useState([]);
  const [alerts, setAlerts]       = useState([]);
  const [traffic, setTraffic]     = useState([]);
  const [connected, setConnected] = useState(false);
  const [activeScene, setActive]  = useState(null);
  const [sceneLoading, setLoading]= useState(false);
  const wsRef    = useRef(null);
  const demoRef  = useRef(null);
  const statsRef = useRef(stats);
  statsRef.current = stats;

  const handlePacket = useCallback((data) => {
    setEvents(prev=>[data,...prev.slice(0,99)]);
    setStats(prev=>({
      ...prev,
      total_packets:prev.total_packets+1,
      total_bytes:prev.total_bytes+(data.bytes||0),
      threats_detected:(data.verdict==="ALERT"||data.verdict==="DROP")?prev.threats_detected+1:prev.threats_detected,
      protocols:{...prev.protocols,[data.app_protocol||data.protocol]:(prev.protocols[data.app_protocol||data.protocol]||0)+1},
    }));
    if(data.verdict==="ALERT"||data.verdict==="DROP")
      setAlerts(prev=>[{...data,type:"threat"},...prev.slice(0,49)]);
  },[]);

  const handleAnomaly = useCallback((data) => {
    setAlerts(prev=>[{...data,type:"anomaly"},...prev.slice(0,49)]);
    setStats(prev=>({...prev,anomalies_detected:prev.anomalies_detected+1}));
  },[]);

  useEffect(()=>{
    // Fonts
    const link = document.createElement("link");
    link.rel="stylesheet";
    link.href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap";
    document.head.appendChild(link);
    // Styles
    const style = document.createElement("style");
    style.textContent=`
      @keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(0,212,170,0.4)}50%{box-shadow:0 0 0 6px rgba(0,212,170,0)}}
      @media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
      *{box-sizing:border-box;margin:0;padding:0}
      button{font-family:inherit}
      ::-webkit-scrollbar{width:4px}
      ::-webkit-scrollbar-track{background:transparent}
      ::-webkit-scrollbar-thumb{background:#30363D;border-radius:4px}
      a:focus-visible,button:focus-visible{outline:2px solid #00D4AA;outline-offset:2px}
    `;
    document.head.appendChild(style);

    tryConnect();
    const iv = setInterval(()=>{
      const now = new Date().toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"});
      setTraffic(p=>[...p.slice(-29),{time:now,packets:statsRef.current.total_packets,threats:statsRef.current.threats_detected}]);
      setStats(p=>({...p,uptime_seconds:p.uptime_seconds+1}));
    },1000);
    return()=>{wsRef.current?.close();clearInterval(demoRef.current);clearInterval(iv);};
  },[]);

  useEffect(()=>{document.body.style.background=t.bg;},[t]);

  function tryConnect(){
    try{
      const ws=new WebSocket(WS);
      ws.onopen=()=>{setConnected(true);clearInterval(demoRef.current);};
      ws.onclose=()=>{setConnected(false);startDemo();};
      ws.onerror=()=>ws.close();
      ws.onmessage=(e)=>{
        const msg=JSON.parse(e.data);
        if(msg.type==="init"){setStats(msg.data.stats);setEvents(msg.data.recent_events||[]);setAlerts(msg.data.recent_alerts||[]);}
        if(msg.type==="packet")  handlePacket(msg.data);
        if(msg.type==="anomaly") handleAnomaly(msg.data);
        if(msg.type==="reset"){setEvents([]);setAlerts([]);setTraffic([]);setStats({total_packets:0,total_bytes:0,threats_detected:0,anomalies_detected:0,protocols:{},uptime_seconds:0});}
      };
      wsRef.current=ws;
    }catch{startDemo();}
  }

  function startDemo(){
    clearInterval(demoRef.current);
    demoRef.current=setInterval(()=>handlePacket(generateDemoEvent()),350);
  }

  async function runScenario(id){
    setLoading(true);setActive(id);
    try{await fetch(`${API}/scenario/${id}`,{method:"POST"});}catch{}
    setLoading(false);
  }

  const fmtBytes = b=>b>1e9?(b/1e9).toFixed(1)+" GB":b>1e6?(b/1e6).toFixed(1)+" MB":b>1e3?(b/1e3).toFixed(1)+" KB":b+" B";
  const fmtUp   = s=>`${String(Math.floor(s/3600)).padStart(2,"0")}:${String(Math.floor((s%3600)/60)).padStart(2,"0")}:${String(s%60).padStart(2,"0")}`;
  const protoPie = Object.entries(stats.protocols).map(([name,value],i)=>({name,value,fill:PROTOCOL_COLORS[i%PROTOCOL_COLORS.length]}));

  const panel = {background:t.bgSecond,border:`1px solid ${t.border}`,borderRadius:12,padding:"1.1rem 1.25rem"};
  const sectionTitle = {fontSize:13,fontWeight:600,color:t.text,marginBottom:12,display:"flex",alignItems:"center",justifyContent:"space-between"};

  return (
    <div style={{fontFamily:"'Inter',system-ui,sans-serif",background:t.bg,color:t.text,
      minHeight:"100vh",padding:"1.25rem",transition:"background 0.2s,color 0.2s"}}>

      <a href="#main" style={{position:"absolute",left:-9999}}>Skip to main content</a>

      {/* Header */}
      <header style={{display:"flex",alignItems:"center",justifyContent:"space-between",
        marginBottom:"1.25rem",flexWrap:"wrap",gap:10}}>
        <div style={{display:"flex",alignItems:"center",gap:12}}>
          <div style={{width:36,height:36,borderRadius:10,
            background:`linear-gradient(135deg,${t.teal}22,${t.violet}22)`,
            border:`1px solid ${t.teal}33`,
            display:"flex",alignItems:"center",justifyContent:"center"}}>
            <Icon d={Icons.shield} size={18} color={t.teal} strokeWidth={2}/>
          </div>
          <div>
            <div style={{fontSize:15,fontWeight:600,letterSpacing:"-0.02em",color:t.text}}>NetSentinel</div>
            <div style={{fontSize:10,color:t.textMuted,fontFamily:"'JetBrains Mono',monospace",
              letterSpacing:"0.04em"}}>DEEP PACKET INSPECTION</div>
          </div>
          <LiveBadge connected={connected} t={t}/>
        </div>

        <div style={{display:"flex",alignItems:"center",gap:10}}>
          <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:12,
            color:t.textSub,display:"flex",alignItems:"center",gap:6}}>
            <Icon d={Icons.clock} size={13} color={t.textMuted}/>
            {fmtUp(stats.uptime_seconds)}
          </div>
          <button onClick={toggleTheme}
            aria-label={`Switch to ${mode==="dark"?"light":"dark"} mode`}
            style={{width:34,height:34,borderRadius:8,border:`1px solid ${t.border}`,
              background:t.bgSecond,cursor:"pointer",color:t.textSub,
              display:"flex",alignItems:"center",justifyContent:"center",
              transition:"all 0.15s"}}
            onMouseEnter={e=>{e.currentTarget.style.borderColor=t.teal;e.currentTarget.style.color=t.teal;}}
            onMouseLeave={e=>{e.currentTarget.style.borderColor=t.border;e.currentTarget.style.color=t.textSub;}}
          >
            <Icon d={mode==="dark"?Icons.sun:Icons.moon} size={15}
              color="currentColor" strokeWidth={1.5}/>
          </button>
        </div>
      </header>

      <main id="main">

        {/* Scenario selector */}
        <section aria-label="Attack scenarios" style={{...panel,marginBottom:"1.25rem"}}>
          <div style={{fontSize:10,fontWeight:600,color:t.textMuted,
            letterSpacing:"0.08em",fontFamily:"'JetBrains Mono',monospace",
            marginBottom:10,display:"flex",alignItems:"center",gap:6}}>
            <Icon d={Icons.play} size={11} color={t.textMuted} fill={t.textMuted} strokeWidth={0}/>
            SELECT SCENARIO
          </div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(175px,1fr))",gap:10}}>
            {SCENARIOS.map(s=>(
              <ScenarioButton key={s.id} s={s} active={activeScene}
                loading={sceneLoading} onClick={runScenario} t={t}/>
            ))}
          </div>
        </section>

        {/* Stat cards */}
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(195px,1fr))",
          gap:12,marginBottom:"1.25rem"}}>
          <StatCard label="Packets"  value={stats.total_packets.toLocaleString()} iconPath={Icons.package} color={t.blue}   t={t}/>
          <StatCard label="Traffic"  value={fmtBytes(stats.total_bytes)}          iconPaths={Icons.wifi}   color={t.teal}   t={t}/>
          <StatCard label="Threats"  value={stats.threats_detected}               iconPaths={Icons.alert}  color={t.red}    t={t}/>
          <StatCard label="Anomalies" value={stats.anomalies_detected}            iconPaths={Icons.brain}  color={t.violet} t={t}/>
        </div>

        {/* Charts */}
        <div style={{display:"grid",gridTemplateColumns:"minmax(0,2fr) minmax(0,1fr)",
          gap:12,marginBottom:"1.25rem"}}>

          <div style={panel}>
            <div style={sectionTitle}>
              <span>Traffic over time</span>
              <div style={{display:"flex",gap:14}}>
                {[{c:t.teal,l:"Packets"},{c:t.red,l:"Threats",dash:true}].map(x=>(
                  <span key={x.l} style={{display:"flex",alignItems:"center",gap:5,
                    fontSize:11,color:t.textSub,fontFamily:"'JetBrains Mono',monospace"}}>
                    <span style={{width:16,height:0,borderTop:`2px ${x.dash?"dashed":"solid"} ${x.c}`,display:"inline-block"}}/>
                    {x.l}
                  </span>
                ))}
              </div>
            </div>
            <ResponsiveContainer width="100%" height={170}>
              <AreaChart data={traffic} margin={{top:0,right:0,bottom:0,left:-20}}>
                <defs>
                  <linearGradient id="tg" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor={t.teal} stopOpacity={0.2}/>
                    <stop offset="95%" stopColor={t.teal} stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={t.borderSub}/>
                <XAxis dataKey="time" tick={{fontSize:10,fill:t.textMuted}}
                  interval="preserveStartEnd" axisLine={false} tickLine={false}/>
                <YAxis tick={{fontSize:10,fill:t.textMuted}} axisLine={false} tickLine={false}/>
                <Tooltip contentStyle={{fontSize:12,background:t.bgThird,
                  border:`1px solid ${t.border}`,borderRadius:8,color:t.text}}
                  cursor={{stroke:t.border}}/>
                <Area type="monotone" dataKey="packets" stroke={t.teal}
                  fill="url(#tg)" strokeWidth={2} dot={false} name="Packets"/>
                <Area type="monotone" dataKey="threats" stroke={t.red}
                  fill="none" strokeWidth={1.5} strokeDasharray="4 2" dot={false} name="Threats"/>
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div style={panel}>
            <div style={sectionTitle}>
              <span>Protocols</span>
              {protoPie.length>0&&(
                <span style={{fontSize:11,color:t.textMuted,
                  fontFamily:"'JetBrains Mono',monospace"}}>
                  {protoPie.length} types
                </span>
              )}
            </div>
            {protoPie.length>0?(
              <>
                <ResponsiveContainer width="100%" height={130}>
                  <PieChart>
                    <Pie data={protoPie} dataKey="value" cx="50%" cy="50%"
                      innerRadius={40} outerRadius={58} strokeWidth={0} paddingAngle={3}>
                      {protoPie.map((e,i)=><Cell key={i} fill={e.fill}/>)}
                    </Pie>
                    <Tooltip contentStyle={{fontSize:12,background:t.bgThird,
                      border:`1px solid ${t.border}`,borderRadius:8,color:t.text}}/>
                  </PieChart>
                </ResponsiveContainer>
                <div style={{display:"flex",flexWrap:"wrap",gap:"5px 10px",marginTop:8}}>
                  {protoPie.map((d,i)=>(
                    <span key={i} style={{display:"flex",alignItems:"center",gap:5,
                      fontSize:11,color:t.textSub,fontFamily:"'JetBrains Mono',monospace"}}>
                      <span style={{width:7,height:7,borderRadius:2,
                        background:d.fill,display:"inline-block"}}/>
                      {d.name}
                    </span>
                  ))}
                </div>
              </>
            ):(
              <div style={{textAlign:"center",padding:"2.5rem 0",color:t.textMuted}}>
                <Icon d={Icons.globe} size={28} color={t.textMuted} strokeWidth={1}/>
                <div style={{fontSize:12,marginTop:10,lineHeight:1.6}}>
                  Select a scenario<br/>to begin analysis
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Bottom */}
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(320px,1fr))",gap:12}}>

          <section aria-label="Alerts" style={panel}>
            <div style={sectionTitle}>
              <span style={{display:"flex",alignItems:"center",gap:7}}>
                <Icon d={Icons.alert} size={14} color={t.red} strokeWidth={1.5}/>
                Alerts & Anomalies
              </span>
              {alerts.length>0&&(
                <span style={{fontSize:10,padding:"2px 8px",borderRadius:99,
                  background:t.red+"18",color:t.red,
                  fontFamily:"'JetBrains Mono',monospace",border:`1px solid ${t.red}33`}}>
                  {alerts.length}
                </span>
              )}
            </div>
            <div role="list" style={{maxHeight:290,overflowY:"auto"}}>
              {alerts.length===0?(
                <div style={{textAlign:"center",padding:"2.5rem 0",color:t.textMuted}}>
                  <Icon d={Icons.check} size={28} color={t.green} strokeWidth={1.5}/>
                  <div style={{fontSize:12,marginTop:10,color:t.textMuted,lineHeight:1.6}}>
                    No alerts detected<br/>
                    <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:11}}>
                      run a scenario above
                    </span>
                  </div>
                </div>
              ):alerts.map((a,i)=><AlertRow key={i} a={a} t={t}/>)}
            </div>
          </section>

          <section aria-label="Live packet feed" style={panel}>
            <div style={sectionTitle}>
              <span style={{display:"flex",alignItems:"center",gap:7}}>
                <Icon d={Icons.activity} size={14} color={t.blue} strokeWidth={1.5}/>
                Live Packet Feed
              </span>
              <span style={{fontSize:10,color:t.textMuted,
                fontFamily:"'JetBrains Mono',monospace"}}>
                {events.length} captured
              </span>
            </div>
            <div style={{maxHeight:290,overflowY:"auto"}}>
              {events.length===0?(
                <div style={{textAlign:"center",padding:"2.5rem 0",color:t.textMuted}}>
                  <Icon d={Icons.radio} size={28} color={t.textMuted} strokeWidth={1}/>
                  <div style={{fontSize:12,marginTop:10,lineHeight:1.6}}>
                    Waiting for packets<br/>
                    <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:11}}>
                      run a scenario above
                    </span>
                  </div>
                </div>
              ):events.slice(0,80).map((e,i)=><PacketRow key={i} e={e} t={t}/>)}
            </div>
          </section>
        </div>
      </main>

      <footer style={{marginTop:"1.5rem",textAlign:"center",fontSize:11,
        color:t.textMuted,fontFamily:"'JetBrains Mono',monospace"}}>
        NetSentinel · Team Bug Busters ·{" "}
        <a href="https://github.com/pranitpawar24/netsentinel"
          style={{color:t.textMuted,textDecoration:"underline"}}
          target="_blank" rel="noopener noreferrer">
          github.com/pranitpawar24/netsentinel
        </a>
      </footer>
    </div>
  );
}
