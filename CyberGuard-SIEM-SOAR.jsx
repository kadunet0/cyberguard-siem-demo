import { useState, useEffect, useRef, useCallback } from "react";
import {
  LineChart, Line, AreaChart, Area, BarChart, Bar,
  RadarChart, Radar, PolarGrid, PolarAngleAxis,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell, PieChart, Pie
} from "recharts";

// ─── CONSTANTS & MOCK DATA ────────────────────────────────────────────────────

const SEVERITY = { CRITICAL: "CRITICAL", HIGH: "HIGH", MEDIUM: "MEDIUM", LOW: "LOW" };
const SEV_COLOR = { CRITICAL: "#ff0055", HIGH: "#ff6600", MEDIUM: "#ffcc00", LOW: "#00ccff" };
const SEV_BG    = { CRITICAL: "rgba(255,0,85,.15)", HIGH: "rgba(255,102,0,.15)", MEDIUM: "rgba(255,204,0,.12)", LOW: "rgba(0,204,255,.1)" };

const MITRE_TACTICS = [
  "Initial Access","Execution","Persistence","Privilege Escalation",
  "Defense Evasion","Credential Access","Discovery","Lateral Movement",
  "Collection","Exfiltration","Impact"
];

const mkAlert = (id, msg, sev, src, dst, tactic, ts) => ({ id, msg, sev, src, dst, tactic, ts, status: "OPEN", mitre: tactic });

const INITIAL_ALERTS = [
  mkAlert(1,"Brute-force SSH detectado",SEVERITY.CRITICAL,"185.220.101.45","10.0.1.20","Credential Access","2025-04-03T14:52:11Z"),
  mkAlert(2,"Exfiltração de dados via DNS tunneling",SEVERITY.CRITICAL,"10.0.2.55","203.0.113.10","Exfiltration","2025-04-03T14:48:03Z"),
  mkAlert(3,"Lateral movement detectado — Pass-the-Hash",SEVERITY.HIGH,"10.0.1.20","10.0.1.35","Lateral Movement","2025-04-03T14:43:22Z"),
  mkAlert(4,"Processo suspeito injetado em lsass.exe",SEVERITY.HIGH,"10.0.1.35","—","Defense Evasion","2025-04-03T14:40:01Z"),
  mkAlert(5,"Scan de portas NMAP detectado",SEVERITY.MEDIUM,"192.168.5.100","10.0.0.0/24","Discovery","2025-04-03T14:35:44Z"),
  mkAlert(6,"Falha de autenticação repetida no AD",SEVERITY.MEDIUM,"10.0.3.88","10.0.1.5","Credential Access","2025-04-03T14:30:19Z"),
  mkAlert(7,"Acesso a arquivo sensível fora do horário",SEVERITY.LOW,"10.0.2.12","fileserver01","Collection","2025-04-03T14:22:05Z"),
  mkAlert(8,"Política de firewall alterada",SEVERITY.MEDIUM,"10.0.1.5","fw-core-01","Defense Evasion","2025-04-03T14:15:33Z"),
  mkAlert(9,"Conexão a IP em blacklist OSINT",SEVERITY.HIGH,"10.0.4.22","45.33.32.156","Command and Control","2025-04-03T14:10:12Z"),
  mkAlert(10,"Ransomware signature detectada em endpoint",SEVERITY.CRITICAL,"10.0.2.78","—","Impact","2025-04-03T14:05:58Z"),
];

const VULNS = [
  { id:"CVE-2024-3400", host:"10.0.1.20", svc:"PAN-OS", cvss:10.0, sev:SEVERITY.CRITICAL, status:"Aberta", desc:"RCE em PAN-OS GlobalProtect" },
  { id:"CVE-2024-21762", host:"10.0.3.15", svc:"FortiOS", cvss:9.6, sev:SEVERITY.CRITICAL, status:"Em Mitigação", desc:"Auth bypass no FortiOS SSL-VPN" },
  { id:"CVE-2023-46805", host:"10.0.1.5",  svc:"Ivanti", cvss:8.2, sev:SEVERITY.HIGH, status:"Aberta", desc:"Auth bypass no Ivanti Connect Secure" },
  { id:"CVE-2024-27198", host:"10.0.2.30", svc:"TeamCity", cvss:9.8, sev:SEVERITY.CRITICAL, status:"Aberta", desc:"Auth bypass no JetBrains TeamCity" },
  { id:"CVE-2023-44487", host:"10.0.4.10", svc:"HTTP/2", cvss:7.5, sev:SEVERITY.HIGH, status:"Corrigida", desc:"HTTP/2 Rapid Reset DDoS" },
  { id:"CVE-2024-1709",  host:"10.0.2.55", svc:"ConnectWise", cvss:10.0, sev:SEVERITY.CRITICAL, status:"Aberta", desc:"Auth bypass no ConnectWise ScreenConnect" },
];

const PLAYBOOKS = [
  { id:1, name:"Bloqueio Automático de IP", trigger:"Brute-force > 5 tentativas", actions:["Adicionar IP à blocklist","Notificar SOC via Slack","Criar ticket JIRA","Log de auditoria"], status:"ATIVO", executions:1243 },
  { id:2, name:"Isolamento de Endpoint Comprometido", trigger:"Ransomware signature detectada", actions:["Isolar máquina da rede","Snapshot de memória","Notificar IR team","Iniciar análise forense"], status:"ATIVO", executions:17 },
  { id:3, name:"Desativação de Usuário Comprometido", trigger:"Credential stuffing detectado", actions:["Desativar conta no AD","Revogar tokens OAuth","Forçar MFA reset","Notificar RH e gestão"], status:"ATIVO", executions:89 },
  { id:4, name:"Resposta a Exfiltração de Dados", trigger:"Anomalia de volume de dados de saída", actions:["Bloquear destino externo","Captura de tráfego (PCAP)","Alerta DLP","Acionar equipe jurídica"], status:"PARADO", executions:4 },
  { id:5, name:"Contenção de Lateral Movement", trigger:"Pass-the-Hash / Pass-the-Ticket", actions:["Segmentar VLAN do host","Resetar Kerberos tickets","Auditoria de credenciais","Varredura de outros hosts"], status:"ATIVO", executions:31 },
];

const USERS = [
  { id:1, name:"Ana Ferreira", role:"SOC Analyst", dept:"Security", lastLogin:"2025-04-03 14:50", mfa:true, status:"Ativo" },
  { id:2, name:"Carlos Lima", role:"SOC Manager", dept:"Security", lastLogin:"2025-04-03 14:45", mfa:true, status:"Ativo" },
  { id:3, name:"Diego Santos", role:"IR Specialist", dept:"Security", lastLogin:"2025-04-03 13:20", mfa:true, status:"Ativo" },
  { id:4, name:"Mariana Costa", role:"Threat Hunter", dept:"Security", lastLogin:"2025-04-03 12:10", mfa:false, status:"Ativo" },
  { id:5, name:"Roberto Alves", role:"Sysadmin", dept:"IT Ops", lastLogin:"2025-04-03 11:30", mfa:true, status:"Bloqueado" },
  { id:6, name:"Fernanda Gomes", role:"CISO", dept:"Executive", lastLogin:"2025-04-03 09:00", mfa:true, status:"Ativo" },
];

const ATTACK_ORIGINS = [
  { country:"Russia", lat:55.7558, lng:37.6176, attacks:342, ip:"185.220.101.45" },
  { country:"China", lat:39.9042, lng:116.4074, attacks:218, ip:"103.75.189.12" },
  { country:"Brazil", lat:-23.5505, lng:-46.6333, attacks:89, ip:"177.54.144.22" },
  { country:"Iran", lat:35.6892, lng:51.3890, attacks:156, ip:"5.160.218.44" },
  { country:"North Korea", lat:39.0392, lng:125.7625, attacks:67, ip:"175.45.176.0" },
  { country:"USA", lat:37.0902, lng:-95.7129, attacks:45, ip:"104.16.100.1" },
];

const genThreatData = () => Array.from({length:24}, (_,i) => ({
  time: `${String(i).padStart(2,"0")}:00`,
  critical: Math.floor(Math.random()*8),
  high: Math.floor(Math.random()*18),
  medium: Math.floor(Math.random()*30),
  low: Math.floor(Math.random()*45),
  total: 0
})).map(d => ({...d, total: d.critical+d.high+d.medium+d.low}));

const genNetworkFlow = () => Array.from({length:12}, (_,i) => ({
  time: `${String(i*2).padStart(2,"0")}:00`,
  inbound: Math.floor(Math.random()*900 + 100),
  outbound: Math.floor(Math.random()*600 + 50),
  blocked: Math.floor(Math.random()*200 + 10),
}));

const genRadarData = () => MITRE_TACTICS.slice(0,8).map(t => ({
  tactic: t.split(" ")[0], value: Math.floor(Math.random()*90+10)
}));

// ─── STYLES ──────────────────────────────────────────────────────────────────
const CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&family=Exo+2:wght@300;400;600;700;800&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg0: #060709;
    --bg1: #0b0d12;
    --bg2: #0f1119;
    --bg3: #141822;
    --bg4: #1a1f2e;
    --border: rgba(0,200,255,.12);
    --border-bright: rgba(0,200,255,.3);
    --cyan: #00ccff;
    --cyan-dim: rgba(0,204,255,.6);
    --green: #00ff9d;
    --red: #ff0055;
    --orange: #ff6600;
    --yellow: #ffcc00;
    --text: #c8d4e8;
    --text-dim: #6b7a96;
    --text-bright: #e8f0ff;
    --font-mono: 'Share Tech Mono', monospace;
    --font-ui: 'Rajdhani', sans-serif;
    --font-display: 'Exo 2', sans-serif;
    --glow-cyan: 0 0 20px rgba(0,204,255,.4);
    --glow-red: 0 0 20px rgba(255,0,85,.5);
  }

  html { -webkit-text-size-adjust: 100%; }

  body { background: var(--bg0); color: var(--text); font-family: var(--font-ui); overflow: hidden; touch-action: manipulation; }

  .app { display: flex; flex-direction: column; height: 100vh; height: 100dvh; background: var(--bg0); }

  /* Scanline overlay */
  .app::before {
    content: '';
    position: fixed; inset: 0; pointer-events: none; z-index: 9999;
    background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,.03) 2px, rgba(0,0,0,.03) 4px);
  }
  .app.scanline-off::before { display: none; }

  /* ── HEADER ── */
  .header {
    display: flex; align-items: center; gap: 16px;
    padding: 0 20px; height: 56px;
    background: linear-gradient(180deg, #0b0f1a 0%, #080b14 100%);
    border-bottom: 1px solid var(--border);
    position: relative; flex-shrink: 0;
  }
  .header::after {
    content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 1px;
    background: linear-gradient(90deg, transparent, var(--cyan), transparent);
    opacity: .4;
  }

  .header-menu-btn {
    display: none;
    flex-shrink: 0;
    align-items: center;
    justify-content: center;
    width: 44px;
    height: 44px;
    margin: 0 6px 0 0;
    padding: 0;
    border: 1px solid var(--border);
    background: var(--bg3);
    color: var(--cyan);
    font-size: 22px;
    line-height: 1;
    border-radius: 3px;
    cursor: pointer;
    font-family: var(--font-ui);
    -webkit-tap-highlight-color: transparent;
  }
  .header-menu-btn:active { background: rgba(0,204,255,.12); }

  .nav-backdrop {
    display: none;
    position: fixed;
    inset: 0;
    z-index: 9998;
    background: rgba(0,0,0,.5);
    -webkit-tap-highlight-color: transparent;
    border: 0;
    padding: 0;
    margin: 0;
    cursor: pointer;
  }

  .logo { display: flex; align-items: center; gap: 10px; }
  .logo-icon {
    width: 34px; height: 34px;
    background: linear-gradient(135deg, var(--cyan), #0066cc);
    clip-path: polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%);
    display: flex; align-items: center; justify-content: center;
    font-size: 14px; font-weight: 700; color: #000;
    font-family: var(--font-display);
    animation: pulse-logo 3s ease-in-out infinite;
  }
  @keyframes pulse-logo {
    0%,100% { box-shadow: 0 0 15px rgba(0,204,255,.5); }
    50% { box-shadow: 0 0 30px rgba(0,204,255,.9); }
  }
  .logo-text { font-family: var(--font-display); font-weight: 800; font-size: 18px; letter-spacing: 2px; color: var(--cyan); }
  .logo-sub { font-family: var(--font-mono); font-size: 9px; color: var(--text-dim); letter-spacing: 3px; margin-top: -2px; }

  .header-sep { width: 1px; height: 30px; background: var(--border); margin: 0 4px; }

  .status-pills { display: flex; gap: 8px; flex: 1; }
  .pill {
    display: flex; align-items: center; gap: 6px;
    padding: 4px 10px; border-radius: 2px;
    font-family: var(--font-mono); font-size: 11px;
    border: 1px solid; cursor: default;
  }
  .pill-dot { width: 6px; height: 6px; border-radius: 50%; animation: blink 1.2s ease-in-out infinite; }
  .pill-green { color: var(--green); border-color: rgba(0,255,157,.25); background: rgba(0,255,157,.06); }
  .pill-green .pill-dot { background: var(--green); box-shadow: 0 0 6px var(--green); }
  .pill-red { color: var(--red); border-color: rgba(255,0,85,.25); background: rgba(255,0,85,.06); }
  .pill-red .pill-dot { background: var(--red); box-shadow: 0 0 6px var(--red); animation-duration: .6s; }
  .pill-yellow { color: var(--yellow); border-color: rgba(255,204,0,.25); background: rgba(255,204,0,.06); }
  .pill-yellow .pill-dot { background: var(--yellow); }
  @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: .3; } }

  .clock {
    font-family: var(--font-mono); font-size: 13px; color: var(--cyan);
    border: 1px solid var(--border); padding: 4px 10px; border-radius: 2px;
    background: rgba(0,204,255,.04);
  }

  .user-badge {
    display: flex; align-items: center; gap: 8px;
    padding: 4px 12px; border-radius: 2px;
    border: 1px solid var(--border); background: var(--bg3);
    font-size: 12px; cursor: pointer;
  }
  .user-avatar {
    width: 24px; height: 24px; border-radius: 50%;
    background: linear-gradient(135deg, var(--cyan), #0066cc);
    display: flex; align-items: center; justify-content: center;
    font-size: 10px; font-weight: 700; color: #000;
  }

  /* ── LAYOUT ── */
  .layout { display: flex; flex: 1; overflow: hidden; }

  /* ── SIDEBAR ── */
  .sidebar {
    width: 200px; background: var(--bg1); border-right: 1px solid var(--border);
    display: flex; flex-direction: column; flex-shrink: 0;
    overflow-y: auto;
  }
  .sidebar::-webkit-scrollbar { width: 3px; }
  .sidebar::-webkit-scrollbar-track { background: transparent; }
  .sidebar::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

  .nav-section { padding: 12px 8px 4px; }
  .nav-label {
    font-family: var(--font-mono); font-size: 9px; letter-spacing: 2px;
    color: var(--text-dim); padding: 0 8px 6px;
    border-bottom: 1px solid var(--border); margin-bottom: 4px;
  }
  .nav-item {
    display: flex; align-items: center; gap: 10px;
    padding: 8px 10px; border-radius: 2px; cursor: pointer;
    font-size: 13px; font-weight: 500; letter-spacing: .5px;
    color: var(--text-dim); transition: all .15s;
    position: relative;
  }
  .nav-item:hover { background: var(--bg3); color: var(--text); }
  .nav-item.active {
    background: rgba(0,204,255,.08); color: var(--cyan);
    border-left: 2px solid var(--cyan);
  }
  .nav-item.active::after {
    content: ''; position: absolute; right: 8px; top: 50%; transform: translateY(-50%);
    width: 4px; height: 4px; border-radius: 50%; background: var(--cyan);
    box-shadow: 0 0 6px var(--cyan);
  }
  .nav-badge {
    margin-left: auto; padding: 1px 6px; border-radius: 10px;
    font-size: 10px; font-weight: 700; font-family: var(--font-mono);
  }
  .badge-red { background: rgba(255,0,85,.2); color: var(--red); border: 1px solid rgba(255,0,85,.4); }
  .badge-cyan { background: rgba(0,204,255,.1); color: var(--cyan); border: 1px solid rgba(0,204,255,.3); }

  .nav-icon { font-size: 14px; width: 18px; text-align: center; }

  .sidebar-footer {
    margin-top: auto; padding: 12px; border-top: 1px solid var(--border);
  }
  .sys-health { font-family: var(--font-mono); font-size: 10px; color: var(--text-dim); }
  .sys-bar { height: 3px; background: var(--bg3); border-radius: 2px; margin: 3px 0 6px; overflow: hidden; }
  .sys-bar-fill { height: 100%; border-radius: 2px; transition: width .5s; }

  /* ── MAIN ── */
  .main { flex: 1; overflow-y: auto; background: var(--bg0); }
  .main::-webkit-scrollbar { width: 5px; }
  .main::-webkit-scrollbar-track { background: var(--bg1); }
  .main::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

  .content { padding: 16px; min-height: 100%; }

  /* ── PAGE HEADER ── */
  .page-header { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 16px; }
  .page-title {
    font-family: var(--font-display); font-size: 22px; font-weight: 700;
    color: var(--text-bright); letter-spacing: 1px;
  }
  .page-sub { font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); margin-top: 2px; }
  .page-actions { display: flex; gap: 8px; }

  /* ── BUTTONS ── */
  .btn {
    padding: 6px 14px; border-radius: 2px; cursor: pointer;
    font-family: var(--font-ui); font-size: 12px; font-weight: 600;
    letter-spacing: .5px; border: 1px solid; transition: all .15s;
    display: inline-flex; align-items: center; gap: 6px;
  }
  .btn-cyan {
    background: rgba(0,204,255,.1); color: var(--cyan); border-color: rgba(0,204,255,.4);
  }
  .btn-cyan:hover { background: rgba(0,204,255,.2); box-shadow: var(--glow-cyan); }
  .btn-red {
    background: rgba(255,0,85,.1); color: var(--red); border-color: rgba(255,0,85,.4);
  }
  .btn-red:hover { background: rgba(255,0,85,.2); }
  .btn-ghost {
    background: transparent; color: var(--text-dim); border-color: var(--border);
  }
  .btn-ghost:hover { background: var(--bg3); color: var(--text); }
  .btn-green {
    background: rgba(0,255,157,.1); color: var(--green); border-color: rgba(0,255,157,.4);
  }

  /* ── CARDS ── */
  .card {
    background: var(--bg2); border: 1px solid var(--border); border-radius: 3px;
    padding: 14px; position: relative; overflow: hidden;
  }
  .card::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 1px;
    background: linear-gradient(90deg, transparent, var(--border-bright), transparent);
  }
  .card-title {
    font-family: var(--font-mono); font-size: 10px; letter-spacing: 2px;
    color: var(--text-dim); margin-bottom: 10px; text-transform: uppercase;
  }

  /* ── METRIC CARDS ── */
  .metric-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 14px; }
  .metric-card {
    background: var(--bg2); border: 1px solid var(--border); border-radius: 3px;
    padding: 14px 16px; position: relative; overflow: hidden;
    transition: border-color .2s;
  }
  .metric-card:hover { border-color: var(--border-bright); }
  .metric-card::after {
    content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 2px;
  }
  .mc-critical::after { background: var(--red); box-shadow: var(--glow-red); }
  .mc-high::after { background: var(--orange); }
  .mc-medium::after { background: var(--yellow); }
  .mc-low::after { background: var(--cyan); }
  .mc-green::after { background: var(--green); }

  .metric-label { font-family: var(--font-mono); font-size: 9px; letter-spacing: 2px; color: var(--text-dim); }
  .metric-value { font-family: var(--font-display); font-size: 34px; font-weight: 800; line-height: 1; margin: 4px 0; }
  .metric-sub { font-family: var(--font-mono); font-size: 10px; color: var(--text-dim); }
  .metric-trend { font-size: 11px; font-weight: 600; }
  .trend-up { color: var(--red); }
  .trend-down { color: var(--green); }

  /* ── GRID LAYOUTS ── */
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }
  .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; margin-bottom: 12px; }
  .grid-6535 { display: grid; grid-template-columns: 65% 35%; gap: 12px; margin-bottom: 12px; }
  .grid-4060 { display: grid; grid-template-columns: 40% 60%; gap: 12px; margin-bottom: 12px; }

  /* ── TABLE ── */
  .tbl { width: 100%; border-collapse: collapse; font-size: 12px; }
  .tbl th {
    font-family: var(--font-mono); font-size: 9px; letter-spacing: 2px;
    color: var(--text-dim); padding: 6px 10px; text-align: left;
    border-bottom: 1px solid var(--border); background: var(--bg1);
  }
  .tbl td { padding: 8px 10px; border-bottom: 1px solid rgba(255,255,255,.04); vertical-align: middle; }
  .tbl tr:hover td { background: rgba(0,204,255,.03); }
  .tbl tr:last-child td { border-bottom: none; }

  .table-wrap {
    width: 100%;
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
    overscroll-behavior-x: contain;
  }
  .table-wrap .tbl { min-width: 560px; }

  /* ── SEVERITY BADGE ── */
  .sev-badge {
    display: inline-flex; align-items: center; gap: 4px;
    padding: 2px 8px; border-radius: 2px;
    font-family: var(--font-mono); font-size: 10px; font-weight: 700;
    letter-spacing: 1px;
  }

  /* ── STATUS BADGE ── */
  .status-badge {
    display: inline-flex; align-items: center; gap: 4px;
    padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600;
  }
  .status-open { background: rgba(255,0,85,.15); color: var(--red); }
  .status-ack { background: rgba(255,204,0,.15); color: var(--yellow); }
  .status-closed { background: rgba(0,255,157,.1); color: var(--green); }
  .status-active { background: rgba(0,255,157,.1); color: var(--green); }
  .status-stopped { background: rgba(255,102,0,.1); color: var(--orange); }
  .status-blocked { background: rgba(255,0,85,.1); color: var(--red); }

  /* ── ATTACK MAP ── */
  .attack-map-container {
    position: relative; background: var(--bg2); border: 1px solid var(--border);
    border-radius: 3px; overflow: hidden; padding: 14px;
  }
  .world-map { width: 100%; height: 320px; position: relative; background: var(--bg1); border-radius: 2px; overflow: hidden; }
  .map-grid {
    position: absolute; inset: 0;
    background-image: linear-gradient(rgba(0,204,255,.06) 1px, transparent 1px),
                      linear-gradient(90deg, rgba(0,204,255,.06) 1px, transparent 1px);
    background-size: 40px 40px;
  }
  .map-point {
    position: absolute; transform: translate(-50%,-50%);
    cursor: pointer;
  }
  .map-dot {
    width: 10px; height: 10px; border-radius: 50%;
    background: var(--red); box-shadow: 0 0 10px var(--red);
    position: relative; z-index: 2;
    animation: map-pulse 2s ease-in-out infinite;
  }
  .map-ring {
    position: absolute; inset: -8px; border-radius: 50%;
    border: 1px solid var(--red); opacity: 0;
    animation: map-ring 2s ease-out infinite;
  }
  @keyframes map-pulse { 0%,100% { transform: scale(1); } 50% { transform: scale(1.3); } }
  @keyframes map-ring {
    0% { transform: scale(.5); opacity: .8; }
    100% { transform: scale(2.5); opacity: 0; }
  }
  .map-tooltip {
    position: absolute; bottom: 130%; left: 50%; transform: translateX(-50%);
    background: var(--bg0); border: 1px solid var(--red);
    padding: 6px 10px; border-radius: 2px; white-space: nowrap;
    font-family: var(--font-mono); font-size: 10px; color: var(--text);
    pointer-events: none; opacity: 0; transition: opacity .2s;
    z-index: 10;
  }
  .map-point:hover .map-tooltip { opacity: 1; }

  .target-dot { background: var(--cyan) !important; box-shadow: 0 0 10px var(--cyan) !important; }
  .target-ring { border-color: var(--cyan) !important; }

  /* ── PLAYBOOK ── */
  .playbook-card {
    background: var(--bg2); border: 1px solid var(--border); border-radius: 3px;
    padding: 14px; margin-bottom: 10px; transition: border-color .2s;
  }
  .playbook-card:hover { border-color: var(--border-bright); }
  .playbook-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
  .playbook-title { font-family: var(--font-display); font-weight: 700; font-size: 15px; color: var(--text-bright); }
  .playbook-trigger { font-family: var(--font-mono); font-size: 10px; color: var(--cyan); margin: 4px 0 10px; }
  .playbook-actions { display: flex; flex-wrap: wrap; gap: 6px; }
  .action-chip {
    padding: 3px 10px; border-radius: 2px; font-size: 11px;
    background: rgba(0,204,255,.08); color: var(--cyan-dim);
    border: 1px solid rgba(0,204,255,.2); font-family: var(--font-mono);
    display: flex; align-items: center; gap: 4px;
  }
  .playbook-footer { display: flex; align-items: center; justify-content: space-between; margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--border); }

  /* ── AI ENGINE ── */
  .ai-meter { position: relative; height: 8px; background: var(--bg3); border-radius: 4px; overflow: hidden; margin: 4px 0 12px; }
  .ai-meter-fill {
    height: 100%; border-radius: 4px;
    background: linear-gradient(90deg, var(--cyan), var(--green));
    box-shadow: 0 0 10px var(--cyan);
    position: relative;
  }
  .ai-meter-fill::after {
    content: ''; position: absolute; inset: 0;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,.3), transparent);
    animation: shimmer 2s linear infinite;
  }
  @keyframes shimmer { 0% { transform: translateX(-100%); } 100% { transform: translateX(100%); } }

  .model-card {
    background: var(--bg3); border: 1px solid var(--border); border-radius: 3px;
    padding: 12px; margin-bottom: 8px;
  }
  .model-name { font-family: var(--font-display); font-weight: 700; font-size: 14px; color: var(--text-bright); }
  .model-meta { font-family: var(--font-mono); font-size: 10px; color: var(--text-dim); margin: 3px 0 8px; }
  .model-stats { display: flex; gap: 16px; }
  .model-stat { font-family: var(--font-mono); font-size: 11px; }
  .model-stat-label { color: var(--text-dim); font-size: 9px; }
  .model-stat-value { color: var(--cyan); font-weight: 700; }

  /* ── ARCH DIAGRAM ── */
  .arch-container { background: var(--bg1); border-radius: 3px; padding: 20px; position: relative; }
  .arch-layer {
    border: 1px dashed rgba(0,204,255,.2); border-radius: 4px; padding: 12px;
    margin-bottom: 12px; position: relative;
  }
  .arch-layer-label {
    position: absolute; top: -10px; left: 12px;
    font-family: var(--font-mono); font-size: 9px; letter-spacing: 2px;
    color: var(--cyan); background: var(--bg1); padding: 0 6px;
  }
  .arch-nodes { display: flex; gap: 10px; flex-wrap: wrap; }
  .arch-node {
    padding: 8px 14px; border-radius: 3px; border: 1px solid;
    font-family: var(--font-mono); font-size: 11px; text-align: center;
    cursor: default; transition: all .2s;
  }
  .arch-node:hover { transform: translateY(-2px); box-shadow: 0 4px 20px rgba(0,0,0,.5); }
  .an-blue { border-color: rgba(0,204,255,.4); background: rgba(0,204,255,.08); color: var(--cyan); }
  .an-green { border-color: rgba(0,255,157,.4); background: rgba(0,255,157,.08); color: var(--green); }
  .an-orange { border-color: rgba(255,102,0,.4); background: rgba(255,102,0,.08); color: var(--orange); }
  .an-red { border-color: rgba(255,0,85,.4); background: rgba(255,0,85,.08); color: var(--red); }
  .an-yellow { border-color: rgba(255,204,0,.4); background: rgba(255,204,0,.08); color: var(--yellow); }
  .an-purple { border-color: rgba(170,0,255,.4); background: rgba(170,0,255,.08); color: #cc66ff; }

  /* ── FILTERS ── */
  .filter-bar { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
  .filter-chip {
    padding: 4px 12px; border-radius: 2px; cursor: pointer;
    font-family: var(--font-mono); font-size: 11px;
    border: 1px solid var(--border); background: var(--bg2);
    color: var(--text-dim); transition: all .15s;
  }
  .filter-chip:hover, .filter-chip.active { border-color: var(--cyan); color: var(--cyan); background: rgba(0,204,255,.08); }

  /* ── TERMINAL ── */
  .terminal {
    background: #020305; border: 1px solid rgba(0,255,157,.2); border-radius: 3px;
    padding: 12px; font-family: var(--font-mono); font-size: 11px;
    max-height: 200px; overflow-y: auto; color: var(--green);
  }
  .terminal-line { margin-bottom: 3px; line-height: 1.5; }
  .term-prompt { color: var(--cyan); }
  .term-cmd { color: var(--text); }
  .term-out { color: rgba(0,255,157,.7); }
  .term-warn { color: var(--yellow); }
  .term-err { color: var(--red); }

  /* ── SCROLLBAR ── */
  ::-webkit-scrollbar { width: 5px; height: 5px; }
  ::-webkit-scrollbar-track { background: var(--bg1); }
  ::-webkit-scrollbar-thumb { background: var(--bg4); border-radius: 3px; }

  /* ── TOOLTIP CUSTOM ── */
  .recharts-tooltip-wrapper .recharts-default-tooltip {
    background: var(--bg2) !important; border: 1px solid var(--border) !important;
    border-radius: 3px !important; font-family: var(--font-mono) !important;
    font-size: 11px !important;
  }

  /* ── VULN SCORE ── */
  .cvss-bar { display: flex; align-items: center; gap: 8px; }
  .cvss-track { flex: 1; height: 4px; background: var(--bg3); border-radius: 2px; overflow: hidden; }
  .cvss-fill { height: 100%; border-radius: 2px; }

  /* ── PULSE TAG ── */
  .live-tag {
    display: inline-flex; align-items: center; gap: 5px;
    font-family: var(--font-mono); font-size: 9px; color: var(--red);
    border: 1px solid rgba(255,0,85,.3); padding: 2px 6px; border-radius: 2px;
    background: rgba(255,0,85,.06);
  }
  .live-tag-dot { width: 5px; height: 5px; border-radius: 50%; background: var(--red); animation: blink .6s infinite; }

  /* ── INPUT ── */
  .search-input {
    background: var(--bg3); border: 1px solid var(--border); border-radius: 2px;
    color: var(--text); font-family: var(--font-mono); font-size: 12px;
    padding: 6px 10px; outline: none; transition: border-color .15s;
  }
  .search-input:focus { border-color: var(--cyan); }
  .search-input::placeholder { color: var(--text-dim); }

  .lab-row { display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-end; margin-bottom: 14px; }
  .lab-field { display: flex; flex-direction: column; gap: 5px; flex: 1; min-width: 120px; }
  .lab-field label { font-family: var(--font-mono); font-size: 10px; color: var(--text-dim); letter-spacing: 1px; }
  .lab-field select.search-input { cursor: pointer; }
  .lab-range { width: 100%; accent-color: var(--cyan); height: 6px; }
  .lab-hint { font-size: 11px; color: var(--text-dim); line-height: 1.55; max-width: 720px; }
  .lab-toggle {
    display: flex; align-items: center; gap: 10px; font-family: var(--font-mono); font-size: 12px;
    color: var(--text-dim); cursor: pointer; user-select: none;
  }
  .lab-toggle input { accent-color: var(--cyan); width: 16px; height: 16px; }

  /* ── TABS ── */
  .tab-bar { display: flex; border-bottom: 1px solid var(--border); margin-bottom: 14px; }
  .tab {
    padding: 8px 16px; cursor: pointer; font-size: 13px; font-weight: 600;
    color: var(--text-dim); border-bottom: 2px solid transparent;
    transition: all .15s; margin-bottom: -1px;
  }
  .tab.active { color: var(--cyan); border-bottom-color: var(--cyan); }
  .tab:hover:not(.active) { color: var(--text); }

  /* ── PROGRESS RING ── */
  .progress-ring-container { display: flex; align-items: center; gap: 12px; }
  .prog-ring { position: relative; }
  .prog-ring svg { transform: rotate(-90deg); }
  .prog-ring-label {
    position: absolute; inset: 0; display: flex; flex-direction: column;
    align-items: center; justify-content: center;
  }

  /* ── FADE IN ── */
  @keyframes fadeUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
  .fade-up { animation: fadeUp .3s ease forwards; }

  @keyframes slideIn { from { opacity: 0; transform: translateX(-10px); } to { opacity: 1; transform: translateX(0); } }

  /* ── MOBILE & TABLETS (touch-first) ── */
  @media (max-width: 900px) {
    body { overflow: auto; overflow-x: hidden; }
    .app { min-height: 100dvh; height: auto; max-height: none; }

    html:has(.app.nav-open),
    body:has(.app.nav-open) {
      overflow: hidden;
      height: 100%;
    }

    .header {
      flex-wrap: wrap;
      height: auto;
      min-height: 52px;
      padding: 8px 10px;
      padding-left: max(10px, env(safe-area-inset-left));
      padding-right: max(10px, env(safe-area-inset-right));
      gap: 8px;
      position: sticky;
      top: 0;
      z-index: 10001;
      background: linear-gradient(180deg, #0b0f1a 0%, #080b14 100%);
    }
    .header-menu-btn { display: flex; }
    .header-sep { display: none; }
    .clock { display: none; }
    .logo-sub { display: none; }
    .logo-text { font-size: 15px; letter-spacing: 1px; }

    .status-pills {
      order: 10;
      flex: 1 1 100%;
      flex-wrap: nowrap;
      overflow-x: auto;
      gap: 6px;
      padding-bottom: 4px;
      -webkit-overflow-scrolling: touch;
      scrollbar-width: thin;
      mask-image: linear-gradient(90deg, #000 92%, transparent 100%);
    }
    .pill {
      flex-shrink: 0;
      font-size: 10px;
      padding: 8px 10px;
      white-space: nowrap;
    }

    .user-badge {
      margin-left: auto;
      padding: 6px 10px;
      min-height: 44px;
      align-items: center;
    }
    .user-badge > div:last-child { display: none; }

    .layout {
      flex: 1 1 auto;
      min-height: 0;
      overflow: visible;
      position: relative;
    }

    .sidebar {
      position: fixed;
      left: 0;
      top: 0;
      bottom: 0;
      width: min(300px, 88vw);
      max-width: 100%;
      z-index: 9999;
      transform: translateX(-100%);
      transition: transform 0.22s ease;
      border-right: 1px solid var(--border);
      padding-top: max(8px, env(safe-area-inset-top));
      padding-bottom: env(safe-area-inset-bottom);
      box-shadow: none;
      -webkit-overflow-scrolling: touch;
    }
    .app.nav-open .sidebar {
      transform: translateX(0);
      box-shadow: 6px 0 28px rgba(0,0,0,.45);
    }
    .app.nav-open .nav-backdrop {
      display: block;
      animation: fadeInBackdrop 0.2s ease forwards;
    }
    @keyframes fadeInBackdrop { from { opacity: 0; } to { opacity: 1; } }

    .nav-item {
      min-height: 48px;
      padding: 12px 12px;
      -webkit-tap-highlight-color: rgba(0,204,255,.12);
      font-size: 14px;
    }
    .nav-section { padding-top: 16px; }
    .sidebar-footer { padding-bottom: max(16px, env(safe-area-inset-bottom)); }

    .main {
      flex: 1 1 auto;
      min-width: 0;
      min-height: 60vh;
      overflow-y: auto;
      -webkit-overflow-scrolling: touch;
      padding-bottom: env(safe-area-inset-bottom);
    }
    .content { padding: 12px max(12px, env(safe-area-inset-right)) max(20px, env(safe-area-inset-bottom)) max(12px, env(safe-area-inset-left)); }

    .page-header { flex-direction: column; align-items: stretch; gap: 12px; }
    .page-title { font-size: 18px; }
    .page-sub { font-size: 10px; line-height: 1.4; }
    .page-actions { flex-wrap: wrap; width: 100%; gap: 8px; }

    .btn {
      min-height: 44px;
      padding: 10px 16px;
      font-size: 13px;
    }

    .metric-grid { grid-template-columns: repeat(2, 1fr); gap: 8px; }
    .metric-value { font-size: 26px !important; }
    .metric-card { padding: 12px; }

    .grid-2, .grid-3, .grid-6535, .grid-4060 { grid-template-columns: 1fr; }

    .filter-bar { gap: 6px; }
    .filter-chip {
      min-height: 40px;
      padding: 8px 12px;
      font-size: 12px;
    }

    .world-map { height: min(260px, 45vh); min-height: 200px; }
    .map-point {
      min-width: 44px;
      min-height: 44px;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .playbook-footer {
      flex-direction: column;
      align-items: stretch;
      gap: 10px;
    }
    .playbook-footer .btn { width: 100%; justify-content: center; }

    .tab {
      flex: 1;
      text-align: center;
      padding: 10px 10px;
      font-size: 12px;
    }
    .tab-bar { overflow-x: auto; -webkit-overflow-scrolling: touch; }

    .recharts-responsive-container { min-width: 0 !important; }
    .recharts-wrapper { max-width: 100%; }

    .iam-metrics-grid { grid-template-columns: repeat(2, 1fr) !important; gap: 8px !important; }
    .vuln-scan-grid { grid-template-columns: 1fr !important; }

    .arch-container { padding: 12px; }
    .arch-node { font-size: 10px; padding: 10px 12px; }

    .terminal { font-size: 11px; max-height: min(220px, 35vh); }

    .table-wrap .tbl.alerts-wide { min-width: 720px; }

    .alerts-toolbar {
      flex-direction: column !important;
      align-items: stretch !important;
    }
    .alerts-toolbar .filter-bar {
      width: 100%;
      overflow-x: auto;
      flex-wrap: nowrap;
      padding-bottom: 4px;
      -webkit-overflow-scrolling: touch;
    }
  }

  @media (max-width: 480px) {
    .metric-grid { grid-template-columns: 1fr; }
    .iam-metrics-grid { grid-template-columns: 1fr !important; }
    .page-title { font-size: 16px; }
  }
`;

// ─── HELPER COMPONENTS ────────────────────────────────────────────────────────

const SevBadge = ({ sev }) => (
  <span className="sev-badge" style={{ color: SEV_COLOR[sev], background: SEV_BG[sev], border: `1px solid ${SEV_COLOR[sev]}40` }}>
    ● {sev}
  </span>
);

const StatusBadge = ({ status }) => {
  const cls = { OPEN:"status-open", ACKNOWLEDGED:"status-ack", CLOSED:"status-closed",
    ATIVO:"status-active", PARADO:"status-stopped", Ativo:"status-active",
    Bloqueado:"status-blocked", Aberta:"status-open", Corrigida:"status-closed", "Em Mitigação":"status-ack"
  }[status] || "status-ack";
  return <span className={`status-badge ${cls}`}>{status}</span>;
};

const CvssBar = ({ score }) => {
  const pct = (score / 10) * 100;
  const color = score >= 9 ? "#ff0055" : score >= 7 ? "#ff6600" : score >= 4 ? "#ffcc00" : "#00ccff";
  return (
    <div className="cvss-bar">
      <div className="cvss-track"><div className="cvss-fill" style={{ width:`${pct}%`, background: color }} /></div>
      <span style={{ fontFamily:"var(--font-mono)", fontSize:11, color, minWidth:28 }}>{score.toFixed(1)}</span>
    </div>
  );
};

const LiveTag = () => (
  <span className="live-tag"><span className="live-tag-dot" />LIVE</span>
);

// ─── CLOCK ───────────────────────────────────────────────────────────────────
const Clock = () => {
  const [time, setTime] = useState(new Date());
  useEffect(() => { const t = setInterval(() => setTime(new Date()), 1000); return () => clearInterval(t); }, []);
  return (
    <div className="clock">
      {time.toISOString().replace("T"," ").split(".")[0]} UTC
    </div>
  );
};

// ─── VIEWS ───────────────────────────────────────────────────────────────────

const DashboardView = ({ alerts }) => {
  const [threatData] = useState(genThreatData);
  const [netData] = useState(genNetworkFlow);
  const [radarData] = useState(genRadarData);
  const [liveMetrics, setLiveMetrics] = useState({ events: 18243, threats: 12, blocked: 4821, score: 67 });

  useEffect(() => {
    const t = setInterval(() => {
      setLiveMetrics(m => ({
        events: m.events + Math.floor(Math.random() * 50),
        threats: Math.max(0, m.threats + (Math.random() > .7 ? 1 : Math.random() > .5 ? -1 : 0)),
        blocked: m.blocked + Math.floor(Math.random() * 10),
        score: Math.max(0, Math.min(100, m.score + (Math.random() > .5 ? 1 : -1)))
      }));
    }, 2000);
    return () => clearInterval(t);
  }, []);

  const pieData = [
    { name:"Critical", value:4, fill:"#ff0055" },
    { name:"High", value:3, fill:"#ff6600" },
    { name:"Medium", value:3, fill:"#ffcc00" },
    { name:"Low", value:2, fill:"#00ccff" },
  ];

  const scoreColor = liveMetrics.score < 40 ? "#ff0055" : liveMetrics.score < 70 ? "#ffcc00" : "#00ff9d";

  return (
    <div className="fade-up">
      <div className="page-header">
        <div>
          <div className="page-title">SOC Dashboard</div>
          <div className="page-sub">MONITORAMENTO EM TEMPO REAL · CYBERGUARD SIEM v3.1.0</div>
        </div>
        <div className="page-actions">
          <LiveTag />
          <button className="btn btn-cyan">⬇ Exportar</button>
          <button className="btn btn-ghost">⚙ Configurar</button>
        </div>
      </div>

      <div className="metric-grid">
        <div className="metric-card mc-critical">
          <div className="metric-label">AMEAÇAS ATIVAS</div>
          <div className="metric-value" style={{ color:"#ff0055" }}>{liveMetrics.threats}</div>
          <div className="metric-sub">↑ 3 na última hora <span className="metric-trend trend-up">+33%</span></div>
        </div>
        <div className="metric-card mc-high">
          <div className="metric-label">EVENTOS / DIA</div>
          <div className="metric-value" style={{ color:"#ff6600" }}>{liveMetrics.events.toLocaleString()}</div>
          <div className="metric-sub">Processados pelo SIEM</div>
        </div>
        <div className="metric-card mc-green">
          <div className="metric-label">CONEXÕES BLOQUEADAS</div>
          <div className="metric-value" style={{ color:"#00ff9d" }}>{liveMetrics.blocked.toLocaleString()}</div>
          <div className="metric-sub">↓ 12% vs ontem <span className="metric-trend trend-down">-12%</span></div>
        </div>
        <div className="metric-card mc-medium">
          <div className="metric-label">SECURITY SCORE</div>
          <div className="metric-value" style={{ color: scoreColor }}>{liveMetrics.score}</div>
          <div className="metric-sub">Índice geral de segurança</div>
        </div>
      </div>

      <div className="grid-6535">
        <div className="card">
          <div className="card-title">VOLUME DE AMEAÇAS — ÚLTIMAS 24H <LiveTag /></div>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={threatData} margin={{ top:5, right:10, left:-20, bottom:0 }}>
              <defs>
                <linearGradient id="gc" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ff0055" stopOpacity={0.4}/>
                  <stop offset="95%" stopColor="#ff0055" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="gh" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ff6600" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#ff6600" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid stroke="rgba(255,255,255,.04)" vertical={false} />
              <XAxis dataKey="time" tick={{ fill:"#6b7a96", fontSize:9, fontFamily:"Share Tech Mono" }} />
              <YAxis tick={{ fill:"#6b7a96", fontSize:9, fontFamily:"Share Tech Mono" }} />
              <Tooltip contentStyle={{ background:"#0f1119", border:"1px solid #1a1f2e", fontSize:11 }} />
              <Area type="monotone" dataKey="critical" stroke="#ff0055" fill="url(#gc)" strokeWidth={1.5} name="Crítico" />
              <Area type="monotone" dataKey="high" stroke="#ff6600" fill="url(#gh)" strokeWidth={1.5} name="Alto" />
              <Line type="monotone" dataKey="medium" stroke="#ffcc00" strokeWidth={1} dot={false} name="Médio" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <div className="card">
          <div className="card-title">DISTRIBUIÇÃO POR SEVERIDADE</div>
          <div style={{ display:"flex", flexDirection:"column", alignItems:"center" }}>
            <ResponsiveContainer width="100%" height={160}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={45} outerRadius={70} paddingAngle={3} dataKey="value">
                  {pieData.map((e, i) => <Cell key={i} fill={e.fill} />)}
                </Pie>
                <Tooltip contentStyle={{ background:"#0f1119", border:"1px solid #1a1f2e", fontSize:11 }} />
              </PieChart>
            </ResponsiveContainer>
            <div style={{ display:"flex", gap:12, fontSize:11, fontFamily:"var(--font-mono)" }}>
              {pieData.map(d => (
                <span key={d.name} style={{ color: d.fill, display:"flex", alignItems:"center", gap:4 }}>
                  ■ {d.name}: {d.value}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-title">TRÁFEGO DE REDE (GBPS) <LiveTag /></div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={netData} margin={{ top:5, right:10, left:-20, bottom:0 }}>
              <CartesianGrid stroke="rgba(255,255,255,.04)" vertical={false} />
              <XAxis dataKey="time" tick={{ fill:"#6b7a96", fontSize:9, fontFamily:"Share Tech Mono" }} />
              <YAxis tick={{ fill:"#6b7a96", fontSize:9, fontFamily:"Share Tech Mono" }} />
              <Tooltip contentStyle={{ background:"#0f1119", border:"1px solid #1a1f2e", fontSize:11 }} />
              <Bar dataKey="inbound" fill="rgba(0,204,255,.5)" name="Entrada" />
              <Bar dataKey="outbound" fill="rgba(0,255,157,.4)" name="Saída" />
              <Bar dataKey="blocked" fill="rgba(255,0,85,.5)" name="Bloqueado" />
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="card">
          <div className="card-title">COBERTURA MITRE ATT&CK</div>
          <ResponsiveContainer width="100%" height={180}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="rgba(0,204,255,.12)" />
              <PolarAngleAxis dataKey="tactic" tick={{ fill:"#6b7a96", fontSize:9, fontFamily:"Share Tech Mono" }} />
              <Radar name="Coverage" dataKey="value" stroke="#00ccff" fill="#00ccff" fillOpacity={0.15} strokeWidth={1.5} />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="card">
        <div className="card-title" style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
          <span>ALERTAS RECENTES</span>
          <LiveTag />
        </div>
        <div className="table-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>#</th><th>MENSAGEM</th><th>SEVERIDADE</th><th>ORIGEM</th>
              <th>TÁTICA MITRE</th><th>TIMESTAMP</th><th>STATUS</th>
            </tr>
          </thead>
          <tbody>
            {alerts.slice(0,6).map(a => (
              <tr key={a.id}>
                <td style={{ fontFamily:"var(--font-mono)", color:"var(--text-dim)", fontSize:11 }}>{String(a.id).padStart(4,"0")}</td>
                <td style={{ color:"var(--text-bright)", fontWeight:600, maxWidth:260 }}>{a.msg}</td>
                <td><SevBadge sev={a.sev} /></td>
                <td style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--orange)" }}>{a.src}</td>
                <td style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--cyan-dim)" }}>{a.tactic}</td>
                <td style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--text-dim)" }}>{a.ts.replace("T"," ").split("Z")[0]}</td>
                <td><StatusBadge status={a.status} /></td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      </div>
    </div>
  );
};

// ─── ATTACK MAP ───────────────────────────────────────────────────────────────
const AttackMapView = () => {
  const [selected, setSelected] = useState(null);
  const [counter, setCounter] = useState(0);

  useEffect(() => {
    const t = setInterval(() => setCounter(c => c + Math.floor(Math.random() * 5 + 1)), 800);
    return () => clearInterval(t);
  }, []);

  // Approximate normalized positions for a simple world map (lon/lat → %)
  const toPos = (lat, lng) => ({
    left: `${((lng + 180) / 360 * 100).toFixed(1)}%`,
    top:  `${((90 - lat) / 180 * 100).toFixed(1)}%`,
  });

  const TARGET = { lat: -15.78, lng: -47.93 }; // Brazil/Brasília

  return (
    <div className="fade-up">
      <div className="page-header">
        <div>
          <div className="page-title">Mapa de Ataques em Tempo Real</div>
          <div className="page-sub">VISUALIZAÇÃO GEOGRÁFICA DE AMEAÇAS · {counter.toLocaleString()} TENTATIVAS DETECTADAS</div>
        </div>
        <div className="page-actions"><LiveTag /></div>
      </div>

      <div className="attack-map-container" style={{ marginBottom:12 }}>
        <div className="world-map">
          <div className="map-grid" />
          {/* Continent shapes (simplified SVG) */}
          <svg style={{ position:"absolute", inset:0, width:"100%", height:"100%", opacity:.15 }} viewBox="0 0 360 180">
            {/* Americas */}
            <path d="M 60 20 L 95 20 L 100 50 L 85 80 L 70 100 L 65 130 L 80 160 L 70 165 L 50 140 L 40 100 L 50 60 Z" fill="#00ccff" />
            {/* Europe */}
            <path d="M 155 25 L 185 20 L 195 35 L 180 55 L 170 50 L 160 45 Z" fill="#00ccff" />
            {/* Africa */}
            <path d="M 160 55 L 190 55 L 195 90 L 185 130 L 170 135 L 158 100 L 155 75 Z" fill="#00ccff" />
            {/* Asia */}
            <path d="M 195 20 L 290 22 L 300 60 L 270 80 L 240 75 L 210 65 L 195 50 Z" fill="#00ccff" />
            {/* Australia */}
            <path d="M 260 110 L 300 108 L 305 135 L 285 140 L 262 135 Z" fill="#00ccff" />
          </svg>

          {ATTACK_ORIGINS.map((o, i) => {
            const pos = toPos(o.lat, o.lng);
            return (
              <div key={i} className="map-point" style={{ ...pos }} onClick={() => setSelected(o)}>
                <div className="map-dot" />
                <div className="map-ring" />
                <div className="map-ring" style={{ animationDelay:".5s" }} />
                <div className="map-tooltip">
                  {o.country} · {o.attacks} ataques · {o.ip}
                </div>
              </div>
            );
          })}

          {/* Target (Brazil) */}
          <div className="map-point" style={toPos(TARGET.lat, TARGET.lng)}>
            <div className="map-dot target-dot" style={{ background:"#00ccff", boxShadow:"0 0 15px #00ccff" }} />
            <div className="map-ring target-ring" style={{ borderColor:"#00ccff" }} />
            <div className="map-tooltip" style={{ borderColor:"#00ccff" }}>🎯 ALVO: Rede Corporativa</div>
          </div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-title">TOP ORIGENS DE ATAQUE</div>
          <div className="table-wrap">
          <table className="tbl">
            <thead><tr><th>PAÍS</th><th>IP</th><th>ATAQUES</th><th>RISCO</th></tr></thead>
            <tbody>
              {ATTACK_ORIGINS.sort((a,b) => b.attacks-a.attacks).map((o,i) => (
                <tr key={i} onClick={() => setSelected(o)} style={{ cursor:"pointer" }}>
                  <td style={{ color:"var(--text-bright)", fontWeight:600 }}>{o.country}</td>
                  <td style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--orange)" }}>{o.ip}</td>
                  <td style={{ fontFamily:"var(--font-mono)", fontSize:12, color:"var(--red)", fontWeight:700 }}>{o.attacks}</td>
                  <td>
                    <div style={{ height:4, background:"var(--bg3)", borderRadius:2, overflow:"hidden", width:80 }}>
                      <div style={{ height:"100%", background:"#ff0055", width:`${Math.min(100,(o.attacks/342)*100)}%`, borderRadius:2 }} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        </div>
        {selected ? (
          <div className="card" style={{ border:"1px solid rgba(255,0,85,.3)" }}>
            <div className="card-title" style={{ color:"var(--red)" }}>DETALHE DO ATAQUE — {selected.country.toUpperCase()}</div>
            <div style={{ fontFamily:"var(--font-mono)", fontSize:12, lineHeight:1.8 }}>
              <div><span style={{ color:"var(--text-dim)" }}>IP de Origem:</span> <span style={{ color:"var(--orange)" }}>{selected.ip}</span></div>
              <div><span style={{ color:"var(--text-dim)" }}>País:</span> <span style={{ color:"var(--text-bright)" }}>{selected.country}</span></div>
              <div><span style={{ color:"var(--text-dim)" }}>Total de Ataques:</span> <span style={{ color:"var(--red)", fontWeight:700 }}>{selected.attacks}</span></div>
              <div><span style={{ color:"var(--text-dim)" }}>Protocolo:</span> <span style={{ color:"var(--cyan)" }}>TCP/443, TCP/22, UDP/53</span></div>
              <div><span style={{ color:"var(--text-dim)" }}>Tipo:</span> <span style={{ color:"var(--yellow)" }}>Brute Force + Port Scan</span></div>
              <div><span style={{ color:"var(--text-dim)" }}>Reputação OSINT:</span> <SevBadge sev="CRITICAL" /></div>
            </div>
            <div style={{ marginTop:14, display:"flex", gap:8 }}>
              <button className="btn btn-red">🚫 Bloquear IP</button>
              <button className="btn btn-cyan">📋 Relatório</button>
            </div>
          </div>
        ) : (
          <div className="card" style={{ display:"flex", alignItems:"center", justifyContent:"center", flexDirection:"column", gap:8, opacity:.5 }}>
            <div style={{ fontSize:32 }}>🗺</div>
            <div style={{ fontFamily:"var(--font-mono)", fontSize:12, color:"var(--text-dim)" }}>Clique em um ponto de ataque para detalhes</div>
          </div>
        )}
      </div>
    </div>
  );
};

// ─── ALERTS VIEW ──────────────────────────────────────────────────────────────
const AlertsView = ({ alerts, setAlerts, onOpenSimulador }) => {
  const [filter, setFilter] = useState("ALL");
  const [search, setSearch] = useState("");

  const filtered = alerts.filter(a => {
    if (filter !== "ALL" && a.sev !== filter) return false;
    if (search && !a.msg.toLowerCase().includes(search.toLowerCase()) && !a.src.includes(search)) return false;
    return true;
  });

  const acknowledge = (id) => setAlerts(prev => prev.map(a => a.id === id ? {...a, status:"ACKNOWLEDGED"} : a));
  const close_alert = (id) => setAlerts(prev => prev.map(a => a.id === id ? {...a, status:"CLOSED"} : a));

  return (
    <div className="fade-up">
      <div className="page-header">
        <div>
          <div className="page-title">Central de Alertas</div>
          <div className="page-sub">GERENCIAMENTO DE INCIDENTES E TRIAGEM</div>
        </div>
        <div className="page-actions">
          <button type="button" className="btn btn-cyan" onClick={() => onOpenSimulador?.()}>+ Criar Alerta</button>
          <button type="button" className="btn btn-ghost">⬇ Exportar CSV</button>
        </div>
      </div>

      <div className="metric-grid">
        {Object.entries(SEVERITY).map(([k,v]) => (
          <div key={k} className="metric-card" style={{ cursor:"pointer" }} onClick={() => setFilter(v === filter ? "ALL" : v)}>
            <div className="metric-label">{v}</div>
            <div className="metric-value" style={{ color: SEV_COLOR[v], fontSize:28 }}>
              {alerts.filter(a => a.sev === v).length}
            </div>
            <div className="metric-sub">{alerts.filter(a => a.sev === v && a.status === "OPEN").length} abertas</div>
          </div>
        ))}
      </div>

      <div className="alerts-toolbar" style={{ display:"flex", gap:8, marginBottom:12, alignItems:"center" }}>
        <input className="search-input" placeholder="🔍 Buscar por mensagem, IP..." value={search} onChange={e => setSearch(e.target.value)} style={{ flex:1 }} />
        <div className="filter-bar" style={{ margin:0 }}>
          {["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(f => (
            <button key={f} className={`filter-chip ${filter === f ? "active":""}`} onClick={() => setFilter(f)}>{f}</button>
          ))}
        </div>
      </div>

      <div className="card" style={{ padding:0 }}>
        <div className="table-wrap">
        <table className="tbl alerts-wide">
          <thead>
            <tr>
              <th>ID</th><th>MENSAGEM</th><th>SEVERIDADE</th><th>ORIGEM</th>
              <th>DESTINO</th><th>TÁTICA MITRE</th><th>TIMESTAMP</th><th>STATUS</th><th>AÇÕES</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(a => (
              <tr key={a.id}>
                <td style={{ fontFamily:"var(--font-mono)", color:"var(--text-dim)", fontSize:11 }}>{String(a.id).padStart(4,"0")}</td>
                <td style={{ color:"var(--text-bright)", fontWeight:600, maxWidth:200 }}>{a.msg}</td>
                <td><SevBadge sev={a.sev} /></td>
                <td style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--orange)" }}>{a.src}</td>
                <td style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--text-dim)" }}>{a.dst}</td>
                <td style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--cyan-dim)" }}>{a.tactic}</td>
                <td style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--text-dim)" }}>{a.ts.replace("T"," ").split("Z")[0]}</td>
                <td><StatusBadge status={a.status} /></td>
                <td>
                  <div style={{ display:"flex", gap:4 }}>
                    {a.status === "OPEN" && <button className="btn btn-ghost" style={{ padding:"2px 8px", fontSize:10 }} onClick={() => acknowledge(a.id)}>ACK</button>}
                    {a.status !== "CLOSED" && <button className="btn btn-green" style={{ padding:"2px 8px", fontSize:10 }} onClick={() => close_alert(a.id)}>✓</button>}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      </div>
    </div>
  );
};

// ─── SOAR VIEW ────────────────────────────────────────────────────────────────
const SoarView = () => {
  const [running, setRunning] = useState(null);
  const [logs, setLogs] = useState([
    { t:"14:52:11", type:"out", msg:"[SOAR] Playbook 'Bloqueio de IP' executado → IP 185.220.101.45 adicionado à blocklist" },
    { t:"14:48:03", type:"warn", msg:"[SOAR] Anomalia de exfiltração detectada → Playbook 4 acionado automaticamente" },
    { t:"14:43:22", type:"err",  msg:"[SOAR] CRÍTICO: Lateral movement confirmado → Isolamento de endpoint iniciado" },
    { t:"14:40:01", type:"out", msg:"[SOAR] Processo lsass.exe monitorado → Coleta forense agendada" },
  ]);

  const run = (pb) => {
    setRunning(pb.id);
    const steps = pb.actions;
    let i = 0;
    const t = setInterval(() => {
      if (i >= steps.length) { clearInterval(t); setRunning(null); return; }
      const now = new Date().toISOString().split("T")[1].split(".")[0];
      setLogs(prev => [{ t: now, type:"out", msg:`[${pb.name}] ✓ ${steps[i]}` }, ...prev]);
      i++;
    }, 600);
  };

  return (
    <div className="fade-up">
      <div className="page-header">
        <div>
          <div className="page-title">SOAR — Resposta Automatizada</div>
          <div className="page-sub">SECURITY ORCHESTRATION, AUTOMATION & RESPONSE</div>
        </div>
        <div className="page-actions">
          <button className="btn btn-cyan">+ Novo Playbook</button>
        </div>
      </div>

      <div className="grid-6535">
        <div>
          {PLAYBOOKS.map(pb => (
            <div key={pb.id} className="playbook-card">
              <div className="playbook-header">
                <div>
                  <div className="playbook-title">{pb.name}</div>
                  <div className="playbook-trigger">⚡ TRIGGER: {pb.trigger}</div>
                </div>
                <StatusBadge status={pb.status} />
              </div>
              <div className="playbook-actions">
                {pb.actions.map((a,i) => (
                  <span key={i} className="action-chip">→ {a}</span>
                ))}
              </div>
              <div className="playbook-footer">
                <span style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--text-dim)" }}>
                  Execuções: <span style={{ color:"var(--cyan)" }}>{pb.executions.toLocaleString()}</span>
                </span>
                <button
                  className="btn btn-cyan"
                  style={{ padding:"4px 12px", fontSize:11 }}
                  onClick={() => run(pb)}
                  disabled={running === pb.id}
                >
                  {running === pb.id ? "⟳ Executando..." : "▶ Executar"}
                </button>
              </div>
            </div>
          ))}
        </div>

        <div>
          <div className="card" style={{ marginBottom:12 }}>
            <div className="card-title">ESTATÍSTICAS SOAR</div>
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:10 }}>
              {[
                { label:"Playbooks Ativos", val:4, color:"#00ff9d" },
                { label:"Execuções Hoje", val:127, color:"#00ccff" },
                { label:"MTTR Médio", val:"4m 22s", color:"#ffcc00" },
                { label:"Alertas Auto-Fechados", val:"83%", color:"#00ff9d" },
              ].map((s,i) => (
                <div key={i} style={{ background:"var(--bg3)", border:"1px solid var(--border)", borderRadius:3, padding:"10px 12px" }}>
                  <div style={{ fontFamily:"var(--font-mono)", fontSize:9, color:"var(--text-dim)", letterSpacing:1 }}>{s.label}</div>
                  <div style={{ fontFamily:"var(--font-display)", fontSize:22, fontWeight:800, color:s.color }}>{s.val}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div className="card-title">LOG DE EXECUÇÃO <LiveTag /></div>
            <div className="terminal">
              {logs.map((l,i) => (
                <div key={i} className="terminal-line">
                  <span className="term-prompt">[{l.t}] </span>
                  <span className={`term-${l.type}`}>{l.msg}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// ─── VULNERABILITIES VIEW ─────────────────────────────────────────────────────
const VulnView = () => {
  const [tab, setTab] = useState("vulns");
  return (
    <div className="fade-up">
      <div className="page-header">
        <div>
          <div className="page-title">Gestão de Vulnerabilidades</div>
          <div className="page-sub">SCANNER INTERNO + INTEGRAÇÃO OPENVAS · PRIORIZAÇÃO CVSS</div>
        </div>
        <div className="page-actions">
          <button className="btn btn-red">🔍 Iniciar Scan</button>
          <button className="btn btn-ghost">⬇ Exportar</button>
        </div>
      </div>

      <div className="metric-grid">
        <div className="metric-card mc-critical">
          <div className="metric-label">CRÍTICAS</div>
          <div className="metric-value" style={{ color:"#ff0055" }}>{VULNS.filter(v => v.sev===SEVERITY.CRITICAL).length}</div>
          <div className="metric-sub">CVSS ≥ 9.0</div>
        </div>
        <div className="metric-card mc-high">
          <div className="metric-label">ALTAS</div>
          <div className="metric-value" style={{ color:"#ff6600" }}>{VULNS.filter(v => v.sev===SEVERITY.HIGH).length}</div>
          <div className="metric-sub">CVSS 7.0–8.9</div>
        </div>
        <div className="metric-card mc-medium">
          <div className="metric-label">TOTAL ABERTAS</div>
          <div className="metric-value" style={{ color:"#ffcc00" }}>{VULNS.filter(v => v.status==="Aberta").length}</div>
          <div className="metric-sub">Aguardando mitigação</div>
        </div>
        <div className="metric-card mc-green">
          <div className="metric-label">CORRIGIDAS</div>
          <div className="metric-value" style={{ color:"#00ff9d" }}>{VULNS.filter(v => v.status==="Corrigida").length}</div>
          <div className="metric-sub">Últimos 30 dias</div>
        </div>
      </div>

      <div className="tab-bar">
        {["vulns","scanner","reports"].map(t => (
          <div key={t} className={`tab ${tab===t?"active":""}`} onClick={() => setTab(t)}>
            {{ vulns:"Vulnerabilidades", scanner:"Scanner", reports:"Relatórios" }[t]}
          </div>
        ))}
      </div>

      {tab === "vulns" && (
        <div className="card" style={{ padding:0 }}>
          <div className="table-wrap">
          <table className="tbl">
            <thead>
              <tr><th>CVE ID</th><th>HOST</th><th>SERVIÇO</th><th>CVSS</th><th>SEVERIDADE</th><th>DESCRIÇÃO</th><th>STATUS</th><th>AÇÕES</th></tr>
            </thead>
            <tbody>
              {VULNS.map((v,i) => (
                <tr key={i}>
                  <td style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--cyan)" }}>{v.id}</td>
                  <td style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--orange)" }}>{v.host}</td>
                  <td style={{ fontSize:12 }}>{v.svc}</td>
                  <td style={{ width:120 }}><CvssBar score={v.cvss} /></td>
                  <td><SevBadge sev={v.sev} /></td>
                  <td style={{ fontSize:11, color:"var(--text-dim)", maxWidth:240 }}>{v.desc}</td>
                  <td><StatusBadge status={v.status} /></td>
                  <td>
                    <button className="btn btn-cyan" style={{ padding:"2px 8px", fontSize:10 }}>📋 Detalhes</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        </div>
      )}

      {tab === "scanner" && (
        <div className="card">
          <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
            <div style={{ background:"var(--bg3)", border:"1px solid var(--border)", borderRadius:3, padding:16 }}>
              <div style={{ fontFamily:"var(--font-display)", fontSize:16, fontWeight:700, color:"var(--text-bright)", marginBottom:8 }}>
                Scanner de Vulnerabilidades Interno
              </div>
              <div className="vuln-scan-grid" style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:10, marginBottom:12 }}>
                {[
                  { label:"Último Scan", val:"2025-04-03 12:00" },
                  { label:"Hosts Verificados", val:"247" },
                  { label:"Próximo Scan", val:"2025-04-04 00:00" },
                ].map((s,i) => (
                  <div key={i}>
                    <div style={{ fontFamily:"var(--font-mono)", fontSize:9, color:"var(--text-dim)", letterSpacing:1 }}>{s.label}</div>
                    <div style={{ fontFamily:"var(--font-mono)", fontSize:13, color:"var(--cyan)" }}>{s.val}</div>
                  </div>
                ))}
              </div>
              <button className="btn btn-red">🔍 Executar Scan Agora</button>
            </div>
            <div style={{ background:"var(--bg3)", border:"1px solid var(--border)", borderRadius:3, padding:16 }}>
              <div style={{ fontFamily:"var(--font-display)", fontSize:16, fontWeight:700, color:"var(--text-bright)", marginBottom:8 }}>
                Integração OpenVAS / GVM
              </div>
              <div style={{ fontFamily:"var(--font-mono)", fontSize:12, color:"var(--green)" }}>✓ Conectado · gvmd v22.4.1 · Tasks: 3 ativas</div>
              <button className="btn btn-ghost" style={{ marginTop:10 }}>⚙ Configurar</button>
            </div>
          </div>
        </div>
      )}

      {tab === "reports" && (
        <div className="card">
          <div style={{ fontFamily:"var(--font-mono)", fontSize:12, color:"var(--text-dim)", textAlign:"center", padding:"40px 0" }}>
            Relatórios de vulnerabilidade disponíveis para exportação (PDF, CSV, JSON)
          </div>
        </div>
      )}
    </div>
  );
};

// ─── IAM VIEW ─────────────────────────────────────────────────────────────────
const IamView = () => (
  <div className="fade-up">
    <div className="page-header">
      <div>
        <div className="page-title">Controle de Acesso (IAM)</div>
        <div className="page-sub">OAUTH2 · JWT · RBAC · LOGS DE AUDITORIA</div>
      </div>
      <div className="page-actions">
        <button className="btn btn-cyan">+ Novo Usuário</button>
        <button className="btn btn-ghost">📋 Log de Auditoria</button>
      </div>
    </div>

    <div className="iam-metrics-grid" style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr 1fr", gap:10, marginBottom:14 }}>
      {[
        { label:"TOTAL USUÁRIOS", val:6, color:"#00ccff" },
        { label:"COM MFA ATIVO", val:5, color:"#00ff9d" },
        { label:"BLOQUEADOS", val:1, color:"#ff0055" },
        { label:"SESSÕES ATIVAS", val:4, color:"#ffcc00" },
      ].map((m,i) => (
        <div key={i} className="metric-card">
          <div className="metric-label">{m.label}</div>
          <div className="metric-value" style={{ color:m.color, fontSize:28 }}>{m.val}</div>
        </div>
      ))}
    </div>

    <div className="grid-6535">
      <div className="card" style={{ padding:0 }}>
        <div style={{ padding:"10px 14px 6px" }} className="card-title">USUÁRIOS & PAPÉIS</div>
        <div className="table-wrap">
        <table className="tbl">
          <thead><tr><th>NOME</th><th>PAPEL</th><th>DEPT</th><th>ÚLTIMO LOGIN</th><th>MFA</th><th>STATUS</th><th>AÇÕES</th></tr></thead>
          <tbody>
            {USERS.map(u => (
              <tr key={u.id}>
                <td style={{ color:"var(--text-bright)", fontWeight:600 }}>{u.name}</td>
                <td style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--cyan)" }}>{u.role}</td>
                <td style={{ fontSize:11, color:"var(--text-dim)" }}>{u.dept}</td>
                <td style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--text-dim)" }}>{u.lastLogin}</td>
                <td>
                  <span style={{ color: u.mfa ? "#00ff9d":"#ff0055", fontFamily:"var(--font-mono)", fontSize:11 }}>
                    {u.mfa ? "✓ ON":"✗ OFF"}
                  </span>
                </td>
                <td><StatusBadge status={u.status} /></td>
                <td><button className="btn btn-ghost" style={{ padding:"2px 8px", fontSize:10 }}>✏</button></td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      </div>

      <div>
        <div className="card" style={{ marginBottom:12 }}>
          <div className="card-title">PERFIS RBAC</div>
          {[
            { role:"CISO", perms:["*"], color:"#ff0055" },
            { role:"SOC Manager", perms:["alerts.*","playbooks.*","users.read","reports.*"], color:"#ff6600" },
            { role:"SOC Analyst", perms:["alerts.read","alerts.ack","playbooks.read"], color:"#ffcc00" },
            { role:"Threat Hunter", perms:["alerts.*","threat-intel.*","hunt.*"], color:"#00ccff" },
            { role:"Sysadmin", perms:["assets.*","vuln.read","logs.read"], color:"#00ff9d" },
          ].map((r,i) => (
            <div key={i} style={{ borderLeft:`3px solid ${r.color}`, paddingLeft:10, marginBottom:10 }}>
              <div style={{ fontFamily:"var(--font-display)", fontWeight:700, fontSize:13, color:"var(--text-bright)" }}>{r.role}</div>
              <div style={{ display:"flex", flexWrap:"wrap", gap:4, marginTop:4 }}>
                {r.perms.map((p,j) => (
                  <span key={j} style={{
                    fontFamily:"var(--font-mono)", fontSize:10, padding:"1px 6px",
                    background:`${r.color}18`, color:r.color, border:`1px solid ${r.color}40`, borderRadius:2
                  }}>{p}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  </div>
);

// ─── AI ENGINE VIEW ───────────────────────────────────────────────────────────
const AiView = () => {
  const [trainProgress, setTrainProgress] = useState(73);
  useEffect(() => {
    const t = setInterval(() => {
      setTrainProgress(p => p >= 100 ? 100 : p + 0.1);
    }, 200);
    return () => clearInterval(t);
  }, []);

  const models = [
    { name:"AnomalyNet v2.3", type:"Detecção de Anomalias (Autoencoder)", acc:"97.4%", fp:"0.8%", trained:"2025-04-01", status:"Produção", events:"18.2K/dia" },
    { name:"ThreatClassifier v1.5", type:"Classificação de Ameaças (XGBoost)", acc:"94.1%", fp:"2.1%", trained:"2025-03-28", status:"Produção", events:"8.7K/dia" },
    { name:"BehaviorLSTM v0.9", type:"Análise Comportamental (LSTM)", acc:"89.7%", fp:"3.4%", trained:"2025-03-15", status:"Staging", events:"—" },
  ];

  return (
    <div className="fade-up">
      <div className="page-header">
        <div>
          <div className="page-title">Motor de IA / Machine Learning</div>
          <div className="page-sub">DETECÇÃO DE ANOMALIAS · CLASSIFICAÇÃO DE AMEAÇAS · PIPELINE CONTÍNUO</div>
        </div>
        <div className="page-actions">
          <button className="btn btn-cyan">▶ Retreinar Modelo</button>
        </div>
      </div>

      <div className="metric-grid">
        {[
          { label:"MODELOS EM PRODUÇÃO", val:2, color:"#00ff9d" },
          { label:"EVENTOS/DIA ANALISADOS", val:"26.9K", color:"#00ccff" },
          { label:"PRECISÃO MÉDIA", val:"95.8%", color:"#00ccff" },
          { label:"AMEAÇAS DETECTADAS POR ML", val:"41%", color:"#ffcc00" },
        ].map((m,i) => (
          <div key={i} className="metric-card">
            <div className="metric-label">{m.label}</div>
            <div className="metric-value" style={{ color:m.color, fontSize:24 }}>{m.val}</div>
          </div>
        ))}
      </div>

      <div className="grid-6535">
        <div>
          {models.map((m,i) => (
            <div key={i} className="model-card">
              <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
                <div>
                  <div className="model-name">{m.name}</div>
                  <div className="model-meta">{m.type} · Treinado: {m.trained}</div>
                </div>
                <StatusBadge status={m.status} />
              </div>
              <div className="model-stats">
                {[
                  { label:"Acurácia", val:m.acc },
                  { label:"Falso Positivo", val:m.fp },
                  { label:"Eventos/Dia", val:m.events },
                ].map((s,j) => (
                  <div key={j} className="model-stat">
                    <div className="model-stat-label">{s.label}</div>
                    <div className="model-stat-value">{s.val}</div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div>
          <div className="card" style={{ marginBottom:12 }}>
            <div className="card-title">PIPELINE DE TREINAMENTO CONTÍNUO</div>
            <div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--text-dim)", marginBottom:6 }}>
              Progresso do ciclo atual
            </div>
            <div className="ai-meter">
              <div className="ai-meter-fill" style={{ width:`${trainProgress}%` }} />
            </div>
            <div style={{ display:"flex", justifyContent:"space-between", fontFamily:"var(--font-mono)", fontSize:11 }}>
              <span style={{ color:"var(--text-dim)" }}>Épocas: 73/100</span>
              <span style={{ color:"var(--cyan)" }}>{trainProgress.toFixed(1)}%</span>
            </div>
            <div style={{ marginTop:10, display:"flex", flexDirection:"column", gap:6 }}>
              {[
                { step:"Ingestão de novos eventos", done:true },
                { step:"Feature engineering", done:true },
                { step:"Treinamento distribuído", done: trainProgress >= 73 },
                { step:"Validação e A/B test", done: trainProgress >= 90 },
                { step:"Deploy automático", done: trainProgress >= 100 },
              ].map((s,i) => (
                <div key={i} style={{ display:"flex", alignItems:"center", gap:8, fontFamily:"var(--font-mono)", fontSize:11 }}>
                  <span style={{ color: s.done ? "#00ff9d":"#6b7a96" }}>{s.done ? "✓":"○"}</span>
                  <span style={{ color: s.done ? "var(--text)":"var(--text-dim)" }}>{s.step}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div className="card-title">FONTES DE THREAT INTEL</div>
            {[
              { name:"MITRE ATT&CK", status:"Sincronizado", updated:"2025-04-03", color:"#00ccff" },
              { name:"AlienVault OTX", status:"Sincronizado", updated:"2025-04-03", color:"#00ff9d" },
              { name:"VirusTotal API", status:"Ativo", updated:"Tempo real", color:"#00ff9d" },
              { name:"Shodan Intelligence", status:"Sincronizado", updated:"2025-04-02", color:"#ffcc00" },
              { name:"Abuse.ch ThreatFox", status:"Sincronizado", updated:"2025-04-03", color:"#00ccff" },
            ].map((f,i) => (
              <div key={i} style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"6px 0", borderBottom:"1px solid var(--border)" }}>
                <div style={{ fontFamily:"var(--font-ui)", fontSize:12, fontWeight:600 }}>{f.name}</div>
                <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                  <span style={{ fontFamily:"var(--font-mono)", fontSize:10, color:"var(--text-dim)" }}>{f.updated}</span>
                  <span style={{ fontFamily:"var(--font-mono)", fontSize:10, color:f.color }}>● {f.status}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

// ─── ARCHITECTURE VIEW ────────────────────────────────────────────────────────
const ArchView = () => (
  <div className="fade-up">
    <div className="page-header">
      <div>
        <div className="page-title">Arquitetura do Sistema</div>
        <div className="page-sub">MICROSERVIÇOS · CLOUD NATIVE · ZERO-TRUST</div>
      </div>
    </div>

    <div className="arch-container">
      <div className="arch-layer">
        <div className="arch-layer-label">CAMADA DE APRESENTAÇÃO</div>
        <div className="arch-nodes">
          <div className="arch-node an-blue">React 18 + TypeScript<br/><small>SOC Dashboard</small></div>
          <div className="arch-node an-blue">GraphQL Client<br/><small>Apollo Client</small></div>
          <div className="arch-node an-blue">WebSocket<br/><small>Real-time Feed</small></div>
          <div className="arch-node an-blue">PWA<br/><small>Alertas Mobile</small></div>
        </div>
      </div>

      <div style={{ textAlign:"center", color:"var(--text-dim)", fontFamily:"var(--font-mono)", fontSize:11, margin:"6px 0" }}>
        ↕ HTTPS/TLS 1.3 · JWT Auth · Rate Limiting
      </div>

      <div className="arch-layer">
        <div className="arch-layer-label">API GATEWAY / BFF</div>
        <div className="arch-nodes">
          <div className="arch-node an-yellow">API Gateway<br/><small>Kong / Traefik</small></div>
          <div className="arch-node an-yellow">Auth Service<br/><small>OAuth2 + JWT</small></div>
          <div className="arch-node an-yellow">GraphQL Gateway<br/><small>Schema Federation</small></div>
          <div className="arch-node an-yellow">Rate Limiter<br/><small>Redis Sliding Window</small></div>
        </div>
      </div>

      <div style={{ textAlign:"center", color:"var(--text-dim)", fontFamily:"var(--font-mono)", fontSize:11, margin:"6px 0" }}>
        ↕ Kafka / RabbitMQ · Event Sourcing · CQRS
      </div>

      <div className="arch-layer">
        <div className="arch-layer-label">MICROSERVIÇOS (NestJS / FastAPI)</div>
        <div className="arch-nodes">
          <div className="arch-node an-green">SIEM Core<br/><small>NestJS</small></div>
          <div className="arch-node an-green">Threat Intel<br/><small>FastAPI + ML</small></div>
          <div className="arch-node an-green">SOAR Engine<br/><small>NestJS Workflows</small></div>
          <div className="arch-node an-green">Vuln Manager<br/><small>FastAPI</small></div>
          <div className="arch-node an-green">IAM Service<br/><small>NestJS + Keycloak</small></div>
          <div className="arch-node an-green">Notification<br/><small>Slack/Teams/Email</small></div>
          <div className="arch-node an-green">Log Collector<br/><small>Syslog/SNMP</small></div>
          <div className="arch-node an-green">AI/ML Service<br/><small>Python + TensorFlow</small></div>
        </div>
      </div>

      <div style={{ textAlign:"center", color:"var(--text-dim)", fontFamily:"var(--font-mono)", fontSize:11, margin:"6px 0" }}>
        ↕ Service Mesh (Istio) · mTLS · Distributed Tracing (Jaeger)
      </div>

      <div className="arch-layer">
        <div className="arch-layer-label">CAMADA DE DADOS</div>
        <div className="arch-nodes">
          <div className="arch-node an-orange">PostgreSQL<br/><small>Usuários, Alertas, Vulns</small></div>
          <div className="arch-node an-orange">MongoDB<br/><small>Logs, Eventos brutos</small></div>
          <div className="arch-node an-orange">Elasticsearch<br/><small>Busca & Analytics</small></div>
          <div className="arch-node an-orange">Redis Cluster<br/><small>Cache & Sessions</small></div>
          <div className="arch-node an-orange">Apache Kafka<br/><small>Event Streaming</small></div>
          <div className="arch-node an-orange">MinIO (S3)<br/><small>Artefatos forenses</small></div>
        </div>
      </div>

      <div className="arch-layer">
        <div className="arch-layer-label">OBSERVABILIDADE & INFRA</div>
        <div className="arch-nodes">
          <div className="arch-node an-purple">Prometheus<br/><small>Métricas</small></div>
          <div className="arch-node an-purple">Grafana<br/><small>Dashboards</small></div>
          <div className="arch-node an-purple">Jaeger<br/><small>Tracing</small></div>
          <div className="arch-node an-purple">ELK Stack<br/><small>Logs Centralizados</small></div>
          <div className="arch-node an-purple">Kubernetes<br/><small>Orquestração</small></div>
          <div className="arch-node an-purple">Docker<br/><small>Containers</small></div>
          <div className="arch-node an-purple">GitHub Actions<br/><small>CI/CD</small></div>
          <div className="arch-node an-purple">Vault (HashiCorp)<br/><small>Secrets Mgmt</small></div>
        </div>
      </div>
    </div>

    <div className="grid-2" style={{ marginTop:12 }}>
      <div className="card">
        <div className="card-title">ENDPOINTS DA API REST</div>
        <div className="terminal" style={{ maxHeight:300 }}>
          {[
            ["GET",  "/api/v1/alerts", "Lista alertas (paginado, filtros)"],
            ["POST", "/api/v1/alerts", "Criar alerta manualmente"],
            ["PATCH","/api/v1/alerts/:id/ack", "Reconhecer alerta"],
            ["GET",  "/api/v1/threats", "Listar ameaças ativas"],
            ["POST", "/api/v1/playbooks/:id/execute", "Executar playbook SOAR"],
            ["GET",  "/api/v1/vulnerabilities", "Listar CVEs detectadas"],
            ["POST", "/api/v1/scan/start", "Iniciar scan de vulnerabilidades"],
            ["GET",  "/api/v1/users", "Listar usuários (RBAC)"],
            ["POST", "/api/v1/users/:id/block", "Bloquear usuário"],
            ["GET",  "/api/v1/intel/feeds", "Listar feeds de threat intel"],
            ["GET",  "/api/v1/metrics/summary", "Resumo de métricas do SOC"],
            ["POST", "/api/v1/webhooks", "Registrar webhook (Slack/Teams)"],
            ["GET",  "/api/v1/export?format=csv", "Exportar dados"],
          ].map(([method, path, desc], i) => (
            <div key={i} className="terminal-line">
              <span style={{ color: { GET:"#00ccff", POST:"#00ff9d", PATCH:"#ffcc00", DELETE:"#ff0055" }[method] || "#fff" }}>
                {method.padEnd(6)}
              </span>
              <span className="term-cmd"> {path} </span>
              <span className="term-out">→ {desc}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="card">
        <div className="card-title">EXEMPLO DE RESPOSTA — GET /api/v1/alerts</div>
        <div className="terminal" style={{ maxHeight:300 }}>
          <div className="terminal-line"><span className="term-out">{"{"}</span></div>
          <div className="terminal-line"><span className="term-out">  "status": "ok",</span></div>
          <div className="terminal-line"><span className="term-out">  "pagination": {"{"} "page": 1, "total": 127 {"}"},</span></div>
          <div className="terminal-line"><span className="term-out">  "data": [</span></div>
          <div className="terminal-line"><span className="term-out">    {"{"}</span></div>
          <div className="terminal-line"><span className="term-out">      "id": "ALT-00001",</span></div>
          <div className="terminal-line"><span className="term-out">      "severity": "CRITICAL",</span></div>
          <div className="terminal-line"><span className="term-out">      "message": "Brute-force SSH detectado",</span></div>
          <div className="terminal-line"><span className="term-out">      "source_ip": "185.220.101.45",</span></div>
          <div className="terminal-line"><span className="term-out">      "destination": "10.0.1.20",</span></div>
          <div className="terminal-line"><span className="term-out">      "mitre_tactic": "Credential Access",</span></div>
          <div className="terminal-line"><span className="term-out">      "mitre_technique": "T1110",</span></div>
          <div className="terminal-line"><span className="term-out">      "status": "OPEN",</span></div>
          <div className="terminal-line"><span className="term-out">      "timestamp": "2025-04-03T14:52:11Z",</span></div>
          <div className="terminal-line"><span className="term-out">      "tenant_id": "corp-001",</span></div>
          <div className="terminal-line"><span className="term-out">      "playbook_triggered": "block-ip-v1"</span></div>
          <div className="terminal-line"><span className="term-out">    {"}"}</span></div>
          <div className="terminal-line"><span className="term-out">  ]</span></div>
          <div className="terminal-line"><span className="term-out">{"}"}</span></div>
        </div>
      </div>
    </div>
  </div>
);

// ─── PLAYGROUND (interactivo — dados só no browser) ─────────────────────────
const MITRE_OPTIONS = [...MITRE_TACTICS, "Command and Control"];

const RANDOM_ALERT_TEMPLATES = [
  { msg:"Phishing reportado por utilizador", sev: SEVERITY.MEDIUM },
  { msg:"Volume DNS anómalo (possível tunneling)", sev: SEVERITY.HIGH },
  { msg:"Nova conta privilegiada criada fora do horário", sev: SEVERITY.HIGH },
  { msg:"USB montado em posto de trabalho sensível", sev: SEVERITY.LOW },
  { msg:"Execução de PowerShell encoded", sev: SEVERITY.CRITICAL },
  { msg:"Falha MFA em série — possível MFA fatigue", sev: SEVERITY.MEDIUM },
  { msg:"Beaconing para domínio recém-registado", sev: SEVERITY.CRITICAL },
  { msg:"Alteração de GPO detectada", sev: SEVERITY.HIGH },
];

const randIp = () => `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;

const PlaygroundView = ({ alerts, setAlerts, sysStats, setSysStats, scanlineOn, setScanlineOn }) => {
  const [msg, setMsg] = useState("");
  const [sev, setSev] = useState(SEVERITY.MEDIUM);
  const [src, setSrc] = useState("192.168.1.50");
  const [dst, setDst] = useState("10.0.0.1");
  const [tactic, setTactic] = useState(MITRE_OPTIONS[0]);

  const appendAlert = (maker) => {
    setAlerts((prev) => {
      const id = Math.max(0, ...prev.map((a) => a.id)) + 1;
      return [maker(id), ...prev];
    });
  };

  const addCustom = () => {
    const text = msg.trim() || "Alerta de teste (simulador)";
    const ts = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const s = src.trim() || randIp();
    const d = dst.trim() || "—";
    appendAlert((id) => mkAlert(id, text, sev, s, d, tactic, ts));
  };

  const addRandom = () => {
    const pick = RANDOM_ALERT_TEMPLATES[Math.floor(Math.random() * RANDOM_ALERT_TEMPLATES.length)];
    const tac = MITRE_OPTIONS[Math.floor(Math.random() * MITRE_OPTIONS.length)];
    const ts = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    appendAlert((id) => mkAlert(id, pick.msg, pick.sev, randIp(), randIp(), tac, ts));
  };

  const undoLast = () => setAlerts((prev) => (prev.length ? prev.slice(1) : prev));

  const resetAll = () => setAlerts(INITIAL_ALERTS.map((a) => ({ ...a })));

  return (
    <div className="fade-up">
      <div className="page-header">
        <div>
          <div className="page-title">Simulador</div>
          <div className="page-sub">MEXE AQUI — alterações só na memória desta página (recarregar repõe tudo)</div>
        </div>
        <div className="page-actions">
          <button type="button" className="btn btn-ghost" onClick={undoLast}>↩ Desfazer último</button>
          <button type="button" className="btn btn-red" onClick={resetAll}>↺ Repor alertas iniciais</button>
        </div>
      </div>

      <p className="lab-hint" style={{ marginBottom: 16 }}>
        Cria alertas fictícios e vê-os de imediato em <strong style={{ color: "var(--cyan)" }}>Alertas</strong> e no contador do menu.
        Isto não envia dados para a internet nem grava no disco.
      </p>

      <div className="card" style={{ marginBottom: 14 }}>
        <div className="card-title">NOVO ALERTA (manual)</div>
        <div className="lab-row">
          <div className="lab-field" style={{ flex: 2, minWidth: 220 }}>
            <label>Mensagem</label>
            <input className="search-input" style={{ width: "100%" }} value={msg} onChange={(e) => setMsg(e.target.value)} placeholder="Ex.: Tentativa de SQLi no portal..." />
          </div>
          <div className="lab-field" style={{ maxWidth: 140 }}>
            <label>Severidade</label>
            <select className="search-input" style={{ width: "100%" }} value={sev} onChange={(e) => setSev(e.target.value)}>
              {Object.values(SEVERITY).map((v) => (
                <option key={v} value={v}>{v}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="lab-row">
          <div className="lab-field">
            <label>IP origem</label>
            <input className="search-input" style={{ width: "100%" }} value={src} onChange={(e) => setSrc(e.target.value)} />
          </div>
          <div className="lab-field">
            <label>Destino</label>
            <input className="search-input" style={{ width: "100%" }} value={dst} onChange={(e) => setDst(e.target.value)} />
          </div>
          <div className="lab-field" style={{ flex: 1.2, minWidth: 180 }}>
            <label>Tática MITRE</label>
            <select className="search-input" style={{ width: "100%" }} value={tactic} onChange={(e) => setTactic(e.target.value)}>
              {MITRE_OPTIONS.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button type="button" className="btn btn-cyan" onClick={addCustom}>+ Adicionar este alerta</button>
          <button type="button" className="btn btn-green" onClick={addRandom}>🎲 Evento aleatório</button>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-title">“SAÚDE” DO SERVIDOR (falso — só UI)</div>
          <div className="lab-field" style={{ marginBottom: 10 }}>
            <label>CPU {sysStats.cpu}%</label>
            <input type="range" className="lab-range" min={0} max={100} value={sysStats.cpu} onChange={(e) => setSysStats((s) => ({ ...s, cpu: +e.target.value }))} />
          </div>
          <div className="lab-field" style={{ marginBottom: 10 }}>
            <label>MEM {sysStats.mem}%</label>
            <input type="range" className="lab-range" min={0} max={100} value={sysStats.mem} onChange={(e) => setSysStats((s) => ({ ...s, mem: +e.target.value }))} />
          </div>
          <div className="lab-field">
            <label>DISK {sysStats.disk}%</label>
            <input type="range" className="lab-range" min={0} max={100} value={sysStats.disk} onChange={(e) => setSysStats((s) => ({ ...s, disk: +e.target.value }))} />
          </div>
        </div>
        <div className="card">
          <div className="card-title">APARÊNCIA</div>
          <label className="lab-toggle">
            <input type="checkbox" checked={scanlineOn} onChange={(e) => setScanlineOn(e.target.checked)} />
            Efeito scanline no ecrã
          </label>
          <p className="lab-hint" style={{ marginTop: 12 }}>
            Agora: <strong style={{ color: "var(--text-bright)" }}>{alerts.length}</strong> alertas na lista.
          </p>
        </div>
      </div>
    </div>
  );
};

// ─── MAIN APP ─────────────────────────────────────────────────────────────────

const NAV = [
  { id:"dashboard", label:"Dashboard", icon:"⬛", section:"MONITORAMENTO" },
  { id:"map",       label:"Mapa de Ataques", icon:"🗺", badge: 6, badgeType:"badge-red", section:"MONITORAMENTO" },
  { id:"alerts",    label:"Alertas", icon:"🔔", badge: null, badgeType:"badge-red", section:"DETECÇÃO" },
  { id:"soar",      label:"SOAR / Playbooks", icon:"⚡", badge:5, badgeType:"badge-cyan", section:"RESPOSTA" },
  { id:"vulns",     label:"Vulnerabilidades", icon:"🛡", badge:4, badgeType:"badge-red", section:"GESTÃO" },
  { id:"iam",       label:"IAM / Acesso", icon:"👤", section:"GESTÃO" },
  { id:"ai",        label:"Motor de IA", icon:"🧠", section:"INTELIGÊNCIA" },
  { id:"arch",      label:"Arquitetura", icon:"🏗", section:"SISTEMA" },
  { id:"play",      label:"Simulador", icon:"🎮", section:"SISTEMA" },
];

export default function App() {
  const [view, setView] = useState("dashboard");
  const [alerts, setAlerts] = useState(INITIAL_ALERTS);
  const [sysStats, setSysStats] = useState({ cpu: 67, mem: 54, disk: 38 });
  const [scanlineOn, setScanlineOn] = useState(true);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") setMobileNavOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const criticalCount = alerts.filter(a => a.sev === SEVERITY.CRITICAL && a.status === "OPEN").length;
  const openCount = alerts.filter(a => a.status === "OPEN").length;

  const navWithBadges = NAV.map(n => {
    if (n.id === "alerts") return { ...n, badge: openCount };
    return n;
  });

  let sections = [];
  navWithBadges.forEach(n => {
    if (!sections.includes(n.section)) sections.push(n.section);
  });

  return (
    <>
      <style>{CSS}</style>
      <div className={`app${scanlineOn ? "" : " scanline-off"}${mobileNavOpen ? " nav-open" : ""}`}>
        {/* HEADER */}
        <header className="header">
          <button
            type="button"
            className="header-menu-btn"
            aria-label={mobileNavOpen ? "Fechar menu" : "Abrir menu de navegação"}
            aria-expanded={mobileNavOpen}
            onClick={() => setMobileNavOpen((o) => !o)}
          >
            {mobileNavOpen ? "✕" : "☰"}
          </button>
          <div className="logo">
            <div className="logo-icon">CG</div>
            <div>
              <div className="logo-text">CYBERGUARD</div>
              <div className="logo-sub">SIEM + SOAR PLATFORM</div>
            </div>
          </div>
          <div className="header-sep" />
          <div className="status-pills">
            <div className="pill pill-green"><span className="pill-dot" />SIEM ONLINE</div>
            {criticalCount > 0 && <div className="pill pill-red"><span className="pill-dot" />{criticalCount} CRÍTICOS ATIVOS</div>}
            <div className="pill pill-yellow"><span className="pill-dot" />ML MODELS: 2/3 ATIVOS</div>
            <div className="pill pill-green"><span className="pill-dot" />SOAR: 4 PLAYBOOKS</div>
            <div className="pill pill-green"><span className="pill-dot" />KAFKA: CONECTADO</div>
          </div>
          <Clock />
          <div className="user-badge">
            <div className="user-avatar">AF</div>
            <div>
              <div style={{ fontSize:12, fontWeight:700, color:"var(--text-bright)" }}>Ana Ferreira</div>
              <div style={{ fontSize:10, color:"var(--cyan)", fontFamily:"var(--font-mono)" }}>SOC Analyst</div>
            </div>
          </div>
        </header>

        <button
          type="button"
          className="nav-backdrop"
          tabIndex={-1}
          aria-label="Fechar menu"
          onClick={() => setMobileNavOpen(false)}
        />

        <div className="layout">
          {/* SIDEBAR */}
          <aside className="sidebar">
            {sections.map(sec => {
              const items = navWithBadges.filter(n => n.section === sec);
              return (
                <div key={sec} className="nav-section">
                  <div className="nav-label">{sec}</div>
                  {items.map(n => (
                    <div
                      key={n.id}
                      className={`nav-item ${view === n.id ? "active" : ""}`}
                      onClick={() => {
                        setView(n.id);
                        setMobileNavOpen(false);
                      }}
                    >
                      <span className="nav-icon">{n.icon}</span>
                      {n.label}
                      {n.badge > 0 && <span className={`nav-badge ${n.badgeType || "badge-cyan"}`}>{n.badge}</span>}
                    </div>
                  ))}
                </div>
              );
            })}

            <div className="sidebar-footer">
              <div className="sys-health">
                <div style={{ display:"flex", justifyContent:"space-between" }}>CPU <span style={{ color:"var(--cyan)" }}>{sysStats.cpu}%</span></div>
                <div className="sys-bar"><div className="sys-bar-fill" style={{ width:`${sysStats.cpu}%`, background:"var(--cyan)" }} /></div>
                <div style={{ display:"flex", justifyContent:"space-between" }}>MEM <span style={{ color:"var(--green)" }}>{sysStats.mem}%</span></div>
                <div className="sys-bar"><div className="sys-bar-fill" style={{ width:`${sysStats.mem}%`, background:"var(--green)" }} /></div>
                <div style={{ display:"flex", justifyContent:"space-between" }}>DISK <span style={{ color:"var(--yellow)" }}>{sysStats.disk}%</span></div>
                <div className="sys-bar"><div className="sys-bar-fill" style={{ width:`${sysStats.disk}%`, background:"var(--yellow)" }} /></div>
              </div>
            </div>
          </aside>

          {/* MAIN CONTENT */}
          <main className="main">
            <div className="content">
              {view === "dashboard" && <DashboardView alerts={alerts} />}
              {view === "map"       && <AttackMapView />}
              {view === "alerts"    && <AlertsView alerts={alerts} setAlerts={setAlerts} onOpenSimulador={() => setView("play")} />}
              {view === "soar"      && <SoarView />}
              {view === "vulns"     && <VulnView />}
              {view === "iam"       && <IamView />}
              {view === "ai"        && <AiView />}
              {view === "arch"      && <ArchView />}
              {view === "play"      && (
                <PlaygroundView
                  alerts={alerts}
                  setAlerts={setAlerts}
                  sysStats={sysStats}
                  setSysStats={setSysStats}
                  scanlineOn={scanlineOn}
                  setScanlineOn={setScanlineOn}
                />
              )}
            </div>
          </main>
        </div>
      </div>
    </>
  );
}
