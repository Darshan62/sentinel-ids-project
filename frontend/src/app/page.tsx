"use client"
import React, { useEffect, useState } from "react";
import { ShieldAlert, Activity, ShieldCheck, Box, Zap, Lock, HardDrive, Filter, Play, Square } from "lucide-react";
import Sidebar from "@/components/Sidebar";
import { useGlobalState } from "@/components/GlobalStateProvider";

interface Packet {
  id: string;
  timestamp: string;
  src_ip: string;
  protocol: string;
  port: string;
  activity: string;
  meaning: string;
  status: "Safe" | "Attack" | "Blocked";
  attackLabel: string;
}

interface Health {
  status: string;
  processed_packets: number;
  avg_latency_ms: number;
  active_blocks: number;
  uptime_seconds: number;
  is_sniffing: boolean;
}

export default function Dashboard() {
  const { packets, metrics } = useGlobalState();
  const [health, setHealth] = useState<Health | null>(null);
  const [sniffingActivating, setSniffingActivating] = useState(false);
  const [blockedHistory, setBlockedHistory] = useState<Packet[]>([]);

  useEffect(() => {
    setBlockedHistory(prev => {
      const newBlocked = packets.filter(p => p.status === 'Blocked');
      const combined = [...newBlocked, ...prev];
      const unique: Packet[] = [];
      const ids = new Set();
      for (const pkt of combined) {
        if (!ids.has(pkt.id)) {
          ids.add(pkt.id);
          unique.push(pkt);
        }
      }
      return unique.slice(0, 100);
    });
  }, [packets]);

  useEffect(() => {
    const fetchHealth = () => {
      fetch("/api/health")
        .then(r => r.json())
        .then(h => setHealth(h))
        .catch(e => console.error("Health fetch error", e));
    };
    
    fetchHealth();
    const interval = setInterval(fetchHealth, 5000);

    return () => {
      clearInterval(interval);
    };
  }, []);

  const toggleSniffing = async () => {
    if (!health) return;
    setSniffingActivating(true);
    const endpoint = health.is_sniffing ? "/api/stop" : "/api/start";
    await fetch(endpoint, { method: "POST" });
    // Force health update
    fetch("/api/health").then(r => r.json()).then(h => {
        setHealth(h);
        setSniffingActivating(false);
    });
  };

  const handleBlockIP = async (ip: string) => {
    await fetch("/api/block_ip", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip })
    });
    // Force health update to show active blocks
    fetch("/api/health").then(r => r.json()).then(h => setHealth(h));
  };

  const handleInject = async (type: string, activity: string) => {
    await fetch("/api/inject_attack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type, activity })
    });
  };

  const handleDownloadLogs = () => {
    window.open("/api/logs/download", "_blank");
  };

  const safePct = metrics.total > 0 ? ((metrics.safe / metrics.total) * 100).toFixed(1) : "100.0";
  const systemSecure = metrics.attack === 0;

  return (
    <div className="flex h-full w-full">
      <Sidebar />
      <main className="flex-1 p-10 overflow-y-auto w-full">
        <div className="flex justify-between items-center mb-8 pb-4 border-b border-surface-high/20">
          <div className="flex items-center gap-6">
            <h1 className="font-sans text-2xl font-bold uppercase tracking-tight">Sentinel IDS</h1>
            {systemSecure ? (
              <div className="flex items-center gap-2 bg-primary/10 px-3 py-1 rounded-full">
                <span className="w-2 h-2 rounded-full bg-primary block"></span>
                <span className="font-mono text-[10px] font-bold text-primary">System Secure</span>
              </div>
            ) : (
              <div className="flex items-center gap-2 bg-error/10 px-3 py-1 rounded-full border border-error/20">
                <span className="w-2 h-2 rounded-full bg-error block animate-pulse-err"></span>
                <span className="font-mono text-[10px] font-bold text-error">Threat Detected</span>
              </div>
            )}
          </div>
          <div className="flex items-center gap-4">
             <button onClick={handleDownloadLogs} className="flex items-center gap-2 bg-surface-high hover:bg-surface-highest transition-colors px-4 py-2 rounded-xl text-xs font-mono font-bold border border-surface-high">
                 <HardDrive size={14} className="text-primary"/> Export CSV
             </button>
             {health && (
                 <button 
                    onClick={toggleSniffing}
                    disabled={sniffingActivating}
                    className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono font-bold uppercase tracking-wider transition-all disabled:opacity-50 ${health.is_sniffing ? 'bg-error/20 text-error hover:bg-error/30 border border-error/50' : 'bg-primary/20 text-primary hover:bg-primary/30 border border-primary/50'}`}
                 >
                     {health.is_sniffing ? <><Square size={14} /> Stop Sniffing</> : <><Play size={14} /> Start Sniffing</>}
                 </button>
             )}
          </div>
        </div>

        {/* Health Matrix */}
        {health && (
          <div className="flex gap-4 mb-4">
             <div className="glass-panel p-3 px-6 flex gap-6 items-center text-xs font-mono">
               <span className="text-primary font-bold"><HardDrive size={12} className="inline mr-2"/>ML Inference Engine: {health.status}</span>
               <span className="text-text-secondary">Latency: {health.avg_latency_ms.toFixed(1)}ms</span>
               <span className="text-text-secondary">Uptime: {Math.floor(health.uptime_seconds)}s</span>
               <span className="text-[#38bdf8] font-bold ml-4">🛡️ Active IPS Blocks: {health.active_blocks}</span>
             </div>
          </div>
        )}

        <div className="mb-8">
          <p className="font-mono text-xs text-primary uppercase">AI-powered Network Security</p>
          <h2 className="font-sans text-4xl font-extrabold tracking-tight mt-1">Real-Time Threat Intelligence</h2>
        </div>

        {/* Metrics Grid */}
        <div className="grid grid-cols-4 gap-6 mb-8">
          <MetricCard title="Total Packets" value={metrics.total.toString()} icon={<Box />} color="primary" />
          <MetricCard title="Safe Traffic" value={`${safePct}%`} icon={<ShieldCheck />} color="primary" />
          <MetricCard title="Attacks Detected" value={metrics.attack.toString()} icon={<Zap />} color="error" pulse={metrics.attack > 0} />
          <MetricCard title="Auto-Mitigated" value={metrics.blocked.toString()} icon={<Lock />} color="tertiary" />
        </div>

        {/* Demo Simulator & Blocked Threats */}
        <div className="grid grid-cols-5 gap-6 mb-8">
          <div className="col-span-2 glass-panel p-6 flex flex-col">
             <h4 className="font-bold flex items-center font-sans gap-2 text-md mb-4 text-text-primary/80">
               <Play className="text-primary" size={16} /> Simulator Control Panel
             </h4>
             <div className="flex flex-col gap-3">
                <button onClick={() => handleInject("DoS Hulk", "HTTP GET Flood")} className="bg-surface-container hover:bg-surface-high border border-surface-high/50 text-xs font-mono py-3 px-4 rounded-xl text-left flex justify-between items-center transition-colors">
                    <span className="text-error font-bold">Trigger DoS Hulk</span>
                    <span className="text-text-secondary">HTTP / 80</span>
                </button>
                <button onClick={() => handleInject("SSH-Patator", "SSH BruteForce Auth")} className="bg-surface-container hover:bg-surface-high border border-surface-high/50 text-xs font-mono py-3 px-4 rounded-xl text-left flex justify-between items-center transition-colors">
                    <span className="text-error font-bold">Trigger SSH-Patator</span>
                    <span className="text-text-secondary">SSH / 22</span>
                </button>
                <button onClick={() => handleInject("DDoS", "UDP Flood")} className="bg-surface-container hover:bg-surface-high border border-surface-high/50 text-xs font-mono py-3 px-4 rounded-xl text-left flex justify-between items-center transition-colors">
                    <span className="text-error font-bold">Trigger DDoS</span>
                    <span className="text-text-secondary">UDP / 53</span>
                </button>
             </div>
          </div>
          <div className="col-span-3 glass-panel p-0 flex flex-col overflow-hidden h-[240px]">
             <div className="p-4 px-6 border-b border-surface-high/30 bg-tertiary/5">
                <h4 className="font-bold flex items-center font-sans gap-2 text-md text-tertiary">
                 <Lock size={16} /> Mitigated / Blocked Threats
               </h4>
             </div>
             <div className="flex-1 overflow-y-auto">
               <table className="w-full text-left text-sm">
                 <tbody>
                   {blockedHistory.length === 0 && (
                      <tr><td className="p-8 text-center text-xs font-mono text-text-secondary">No blocked threats in current session.</td></tr>
                   )}
                   {blockedHistory.map(pkt => (
                     <tr key={pkt.id} className="border-b border-surface-high/10 bg-tertiary/5 hover:bg-tertiary/10">
                       <td className="p-3 px-6 font-mono text-xs text-text-secondary">{pkt.timestamp}</td>
                       <td className="p-3 font-mono text-xs text-tertiary font-bold">{pkt.src_ip}</td>
                       <td className="p-3 text-xs text-text-primary/70">{pkt.protocol}/{pkt.port}</td>
                       <td className="p-3 text-xs font-bold text-error">{pkt.attackLabel}</td>
                     </tr>
                   ))}
                 </tbody>
               </table>
             </div>
          </div>
        </div>

        {/* Traffic */}
        <div className="grid grid-cols-3 gap-6">
          <div className="col-span-2 glass-panel overflow-hidden h-[600px] flex flex-col">
             <div className="flex justify-between items-center p-6 border-b border-surface-high/30">
               <h4 className="font-bold flex items-center font-sans gap-2 text-lg">
                 <Activity className="text-primary" size={20} /> Live Traffic Stream
               </h4>
               <span className="font-mono bg-surface-container px-3 py-1 rounded-full text-[10px] text-text-secondary"> WS_CONNECTED </span>
             </div>
             <div className="overflow-x-auto flex-1">
               <table className="w-full text-left border-collapse text-sm">
                 <thead>
                   <tr className="bg-surface-container/50 text-text-secondary font-mono text-[10px] tracking-wider uppercase sticky top-0">
                     <th className="p-4 font-normal">Timestamp</th>
                     <th className="p-4 font-normal">Protocol</th>
                     <th className="p-4 font-normal">Activity / Details</th>
                     <th className="p-4 font-normal">Mitigation Action</th>
                     <th className="p-4 font-normal">Status</th>
                   </tr>
                 </thead>
                 <tbody>
                   {packets.map(pkt => (
                     <tr key={pkt.id} className={`border-b border-surface-high/10 ${pkt.status === 'Attack' ? 'bg-error/5' : pkt.status === 'Blocked' ? 'bg-tertiary/5' : ''}`}>
                       <td className={`p-4 font-mono text-xs ${pkt.status === 'Attack' ? 'text-error' : 'text-text-secondary'}`}>{pkt.timestamp}<br/><span className="text-[10px] opacity-50">{pkt.src_ip}</span></td>
                       <td className="p-4 font-mono text-xs font-bold text-text-primary/70">{pkt.protocol} <br/><span className="text-[10px] opacity-50 font-normal">{pkt.port}</span></td>
                       <td className={`p-4 font-bold ${pkt.status === 'Attack' ? 'text-error' : pkt.status === 'Blocked' ? 'text-tertiary' : 'text-primary'}`}>
                           {pkt.activity}
                           <div className="text-[11px] font-normal text-text-primary/60 mt-1">{pkt.meaning}</div>
                       </td>
                       <td className="p-4">
                         {pkt.status === 'Attack' && pkt.src_ip !== "0.0.0.0" && (
                           <button onClick={() => handleBlockIP(pkt.src_ip)} className="bg-error/10 hover:bg-error/20 border border-error/50 text-error px-3 py-1.5 rounded-lg text-xs font-mono transition-colors">
                             Block IP
                           </button>
                         )}
                         {pkt.status === 'Blocked' && (
                             <span className="text-tertiary font-mono text-xs flex items-center gap-1"><Lock size={12}/> Automatically Dropped</span>
                         )}
                       </td>
                       <td className="p-4">
                         {pkt.status === 'Attack' ? (
                           <span className="flex items-center gap-2 text-error font-medium">
                             <span className="w-1.5 h-1.5 rounded-full bg-error animate-pulse-err"></span>
                             Threat {pkt.attackLabel && `[${pkt.attackLabel}]`}
                           </span>
                         ) : pkt.status === 'Blocked' ? (
                             <span className="flex items-center gap-2 text-tertiary font-medium">
                             <span className="w-1.5 h-1.5 rounded-full bg-tertiary"></span> Blocked
                           </span>
                         ) : (
                           <span className="flex items-center gap-2 text-primary font-medium">
                             <span className="w-1.5 h-1.5 rounded-full bg-primary"></span> Safe
                           </span>
                         )}
                       </td>
                     </tr>
                   ))}
                 </tbody>
               </table>
             </div>
          </div>
          <div className="col-span-1 glass-panel flex flex-col h-[600px]">
             <div className="p-6 border-b border-surface-high/30">
                <h4 className="font-bold flex items-center font-sans gap-2 text-lg">
                 <Zap className="text-error" size={20} /> Active Incidents
               </h4>
             </div>
             <div className="p-4 flex-1 overflow-y-auto flex flex-col gap-4">
               {metrics.attack > 0 && (
                 <div className="bg-[#93000a]/20 p-4 rounded-2xl border border-error/20 shadow-[0_0_15px_rgba(255,180,171,0.15)]">
                   <div className="flex justify-between items-center mb-2">
                     <span className="font-mono text-error text-[10px] font-bold">⚠️ ATTACK DETECTED</span>
                     <span className="text-[10px] text-error/60 font-mono">LIVE</span>
                   </div>
                   <p className="text-xs font-medium text-[#ffdad6] m-0">Threat logged. Waiting for operator IPS mitigation.</p>
                 </div>
               )}
               <div className="bg-surface-highest/50 p-4 rounded-2xl border border-surface-high/30">
                 <div className="flex justify-between items-center mb-2">
                     <span className="font-mono text-primary text-[10px] font-bold">SYSTEM NOTICE</span>
                     <span className="text-[10px] text-text-secondary font-mono">ACTIVE</span>
                   </div>
                   <p className="text-xs font-medium text-text-primary m-0">ML Engine WebSocket online and listening.</p>
               </div>
             </div>
          </div>
        </div>
      </main>
    </div>
  );
}

function MetricCard({ title, value, icon, color, pulse }: { title: string, value: string, icon: React.ReactNode, color: 'primary' | 'error' | 'tertiary', pulse?: boolean }) {
  const colorMap = {
    primary: 'text-primary bg-primary/10 border-primary',
    error: 'text-error bg-error/10 border-error',
    tertiary: 'text-tertiary bg-tertiary/10 border-tertiary'
  };
  const dotColor = {
    primary: 'bg-primary shadow-[0_0_8px_rgba(123,208,255,1)]',
    error: 'bg-error shadow-[0_0_8px_rgba(255,180,171,1)]',
    tertiary: 'bg-tertiary shadow-[0_0_8px_rgba(255,179,173,1)]'
  };

  return (
    <div className="glass-panel p-5 flex flex-col">
      <div className="flex justify-between items-start mb-4">
        <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${colorMap[color].split(' ')[0]} ${colorMap[color].split(' ')[1]}`}>
          {icon}
        </div>
        <span className={`w-2 h-2 rounded-full ${dotColor[color]} ${pulse ? 'animate-pulse-err' : ''}`}></span>
      </div>
      <p className="font-mono text-[10px] text-text-secondary mb-1 uppercase tracking-wider">{title}</p>
      <h3 className="font-sans text-3xl font-extrabold">{value}</h3>
    </div>
  );
}
