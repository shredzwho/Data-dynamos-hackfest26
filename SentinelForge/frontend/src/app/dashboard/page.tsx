"use client";

import { useEffect, useState, useRef } from "react";
import { useRouter } from "next/navigation";
import { io, Socket } from "socket.io-client";
import { motion, AnimatePresence } from "framer-motion";
import { 
  ShieldAlert, Activity, Cpu, Network, Server, 
  Terminal, ShieldCheck, X, Search, CheckCircle2,
  AlertTriangle, Clock, HardDrive
} from "lucide-react";

interface LogEntry {
  id: string;
  source: string;
  message: string;
  type: "info" | "warn" | "error" | "success";
  time: string;
}

interface NodeDetail {
  id: string;
  ip: string;
  mac: string;
  os: string;
  cpu: number;
  ram: number;
  isInfected: boolean;
}

export default function ProfessionalDashboard() {
  const router = useRouter();
  const [socket, setSocket] = useState<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [uptime, setUptime] = useState("00:00:00");
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [activeThreats, setActiveThreats] = useState(0);
  const [auditScore, setAuditScore] = useState(98);
  const [nodes, setNodes] = useState<NodeDetail[]>([]);
  const [selectedNode, setSelectedNode] = useState<NodeDetail | null>(null);
  
  const [cpuLoad, setCpuLoad] = useState(0);
  const [netTraffic, setNetTraffic] = useState(0);
  
  const logsEndRef = useRef<HTMLDivElement>(null);
  const startTime = useRef(Date.now());

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/login");
      return;
    }

    const initialNodes: NodeDetail[] = Array.from({ length: 12 }, (_, i) => ({
      id: `WS-ENT-${(i + 1).toString().padStart(2, "0")}`,
      ip: `10.0.1.${50 + i}`,
      mac: `00:1B:44:${Math.floor(Math.random()*90+10)}:3A:B${i}`,
      os: "Windows 11 Enterprise 22H2",
      cpu: Math.floor(Math.random() * 30) + 5,
      ram: Math.floor(Math.random() * 8) + 2,
      isInfected: false
    }));
    setNodes(initialNodes);

    const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";
    const newSocket = io(backendUrl, { auth: { token } });
    
    newSocket.on("connect", () => {
      setIsConnected(true);
      addLog("System", "WebSocket Connection Established", "success");
    });
    
    newSocket.on("disconnect", () => {
      setIsConnected(false);
      addLog("System", "WebSocket Disconnected", "error");
    });

    newSocket.on("dashboard_events", (data: any) => {
      if (data.type === "THREAT") {
        setActiveThreats(prev => prev + 1);
        setNodes(prev => {
          const newNodes = [...prev];
          const randomIdx = Math.floor(Math.random() * newNodes.length);
          newNodes[randomIdx].isInfected = true;
          return newNodes;
        });
        addLog(data.model || "Network", `Threat Detected: ${data.detail}`, "error");
      } else if (data.type === "AUDIT_RESULT") {
        setAuditScore(data.score);
        addLog("Audit", `Compliance scan completed. Score: ${data.score}%`, data.score < 70 ? "warn" : "success");
      } else if (data.type === "HEARTBEAT") {
        setCpuLoad(data.cpu);
        setNetTraffic(data.net_mbps);
      } else if (data.type === "SUPERVISOR") {
        addLog(data.model || "SOC_LLM", `🔥 ${data.detail}`, "warn");
      } else {
        addLog(data.model || "System", JSON.stringify(data.detail || data), "info");
      }
    });

    setSocket(newSocket);
    
    const timer = setInterval(() => {
      const diff = Math.floor((Date.now() - startTime.current) / 1000);
      const h = String(Math.floor(diff / 3600)).padStart(2, "0");
      const m = String(Math.floor((diff % 3600) / 60)).padStart(2, "0");
      const s = String(diff % 60).padStart(2, "0");
      setUptime(`${h}:${m}:${s}`);
    }, 1000);

    return () => {
      clearInterval(timer);
      newSocket.disconnect();
    };
  }, [router]);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const addLog = (source: string, message: string, type: "info" | "warn" | "error" | "success" = "info") => {
    const newLog: LogEntry = {
      id: Math.random().toString(36).substring(7),
      source,
      message,
      type,
      time: new Date().toLocaleTimeString([], { hour12: false })
    };
    setLogs(prev => [...prev, newLog].slice(-50));
  };

  const triggerAudit = () => {
    addLog("Admin", "Manual Audit Initiated. Waking Log Model...", "warn");
    if (socket) socket.emit("trigger_audit", {});
  };

  const handleIsolate = async () => {
    if (!selectedNode) return;
    
    try {
      const token = localStorage.getItem("token");
      const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";
      
      await fetch(`${backendUrl}/api/quarantine/${selectedNode.id}`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${token}` }
      });
      
      addLog("Admin", `Isolation command confirmed by server for ${selectedNode.id}`, "warn");
      setNodes(prev => prev.map(n => n.id === selectedNode.id ? { ...n, isInfected: false } : n));
      setSelectedNode(null);
    } catch (err) {
      addLog("System", `Failed to quarantine ${selectedNode.id}`, "error");
    }
  };



  return (
    <div className="min-h-screen bg-slate-950 text-slate-300 font-sans p-4 md:p-8 flex flex-col h-screen overflow-hidden">
      
      {/* Top Navigation Bar */}
      <header className="flex justify-between items-center mb-8 shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center rounded-xl shadow-lg shadow-blue-500/20">
            <ShieldCheck size={24} className="text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white tracking-tight">SentinelForge</h1>
            <p className="text-xs text-slate-500 font-medium">Enterprise Security Platform</p>
          </div>
        </div>
        
        <div className="flex items-center gap-6 bg-slate-900/50 px-6 py-3 rounded-full border border-slate-800 backdrop-blur-md">
          <div className="flex items-center gap-2 text-sm">
            <Clock size={16} className="text-slate-500" />
            <span className="font-mono">{uptime}</span>
          </div>
          <div className="h-4 w-px bg-slate-800" />
          <div className="flex items-center gap-2 text-sm">
            <div className={`w-2 h-2 rounded-full ${isConnected ? "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]" : "bg-rose-500 animate-pulse"}`} />
            <span className={isConnected ? "text-emerald-400 font-medium" : "text-rose-400 font-medium"}>
              {isConnected ? "Connected" : "Disconnected"}
            </span>
          </div>
        </div>
      </header>

      {/* Main Grid Layout */}
      <div className="grid grid-cols-1 xl:grid-cols-[1fr_350px] gap-8 flex-1 min-h-0">
        
        {/* Left Content Area */}
        <div className="flex flex-col gap-8 min-h-0">
          
          {/* KPI Stat Cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 shrink-0">
            {[
              { title: "Monitored Endpoints", value: nodes.length, icon: Server, color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/20" },
              { title: "Avg Network Traffic", value: `${netTraffic} Mbps`, icon: Activity, color: "text-indigo-400", bg: "bg-indigo-500/10", border: "border-indigo-500/20", sparkline: "bg-indigo-500" },
              { title: "Avg CPU Load", value: `${cpuLoad}%`, icon: Cpu, color: "text-violet-400", bg: "bg-violet-500/10", border: "border-violet-500/20", sparkline: "bg-violet-500" },
              { title: "Active Security Threats", value: activeThreats, icon: AlertTriangle, color: "text-rose-400", bg: "bg-rose-500/10", border: "border-rose-500/30", isDanger: activeThreats > 0 }
            ].map((stat, i) => (
              <div key={i} className={`bg-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col relative overflow-hidden transition-colors ${stat.isDanger ? 'bg-rose-950/20 border-rose-900/50' : ''}`}>
                <div className="flex justify-between items-start mb-4">
                  <span className="text-sm font-medium text-slate-400">{stat.title}</span>
                  <div className={`p-2 rounded-lg ${stat.bg} ${stat.color}`}>
                    <stat.icon size={18} />
                  </div>
                </div>
                <div className={`text-3xl font-bold font-sans tracking-tight mt-auto ${stat.isDanger ? 'text-rose-500' : 'text-slate-100'}`}>
                  {stat.value}
                </div>
              </div>
            ))}
          </div>

          {/* System Nodes Grid */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl flex flex-col p-6 min-h-[250px] shrink-0">
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-base font-semibold text-slate-200 flex items-center gap-2">
                <Network size={18} className="text-blue-400" />
                Active Workstations
              </h2>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-4 overflow-y-auto custom-scrollbar pr-2 min-h-0">
              {nodes.map(node => (
                <motion.div 
                  key={node.id}
                  whileHover={{ scale: 1.03, y: -2 }}
                  onClick={() => setSelectedNode(node)}
                  className={`p-4 rounded-xl border cursor-pointer transition-all flex flex-col gap-2 ${
                    node.isInfected 
                      ? "bg-rose-950/30 border-rose-500/50 shadow-[0_4px_20px_rgba(225,29,72,0.15)]" 
                      : "bg-slate-950/50 border-slate-800 hover:border-slate-600 hover:bg-slate-800/50 hover:shadow-lg"
                  }`}
                >
                  <div className="flex justify-between items-start">
                    <Server size={18} className={node.isInfected ? "text-rose-400" : "text-slate-500"} />
                    <div className={`w-2 h-2 rounded-full ${
                      node.isInfected ? "bg-rose-500 animate-pulse shadow-[0_0_8px_rgba(244,63,94,0.6)]" : "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.4)]"
                    }`} />
                  </div>
                  <div className="mt-2">
                    <div className="text-sm font-semibold text-slate-200">{node.id}</div>
                    <div className="text-xs font-mono text-slate-500 mt-1">{node.ip}</div>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>

          {/* Event Stream Terminal */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl flex flex-col flex-1 min-h-0 overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-800 flex justify-between items-center bg-slate-950/30">
              <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                <Terminal size={18} className="text-slate-400" />
                Agentic Stream Output
              </h2>
              <button 
                onClick={() => setLogs([])}
                className="text-xs font-medium text-slate-500 hover:text-slate-300 transition-colors"
              >
                Clear Stream
              </button>
            </div>
            <div className="flex-1 p-6 overflow-y-auto font-mono text-sm space-y-3 custom-scrollbar">
              <AnimatePresence initial={false}>
                {logs.map((log) => (
                  <motion.div 
                    key={log.id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className={`flex items-start gap-4 break-words ${
                      log.type === "error" ? "text-rose-400" :
                      log.type === "warn" ? "text-amber-400" :
                      log.type === "success" ? "text-emerald-400" :
                      "text-slate-300"
                    }`}
                  >
                    <span className="text-slate-500 shrink-0 mt-0.5">[{log.time}]</span>
                    <span className="font-semibold text-indigo-400 shrink-0 mt-0.5 w-[80px]">[{log.source}]</span>
                    <span className="leading-relaxed opacity-90">{log.message}</span>
                  </motion.div>
                ))}
              </AnimatePresence>
              <div ref={logsEndRef} className="h-4" />
            </div>
          </div>

        </div>

        {/* Right Sidebar - Compliance & Agents */}
        <div className="flex flex-col gap-8 min-h-0">
          
          {/* Security Audit Score */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 flex flex-col items-center justify-center relative overflow-hidden shrink-0">
            <div className="absolute inset-0 bg-gradient-to-br from-indigo-500/5 to-purple-500/5 pointer-events-none" />
            
            <h3 className="text-sm font-medium text-slate-400 uppercase tracking-widest mb-6 w-full text-center">
              Security Compliance
            </h3>
            
            <div className="relative flex items-center justify-center mb-8">
              {/* Fake circular gauge background */}
              <svg className="w-40 h-40 transform -rotate-90">
                <circle cx="80" cy="80" r="70" stroke="currentColor" strokeWidth="8" fill="transparent" className="text-slate-800" />
                <motion.circle 
                  initial={{ strokeDashoffset: 440 }}
                  animate={{ strokeDashoffset: 440 - (440 * auditScore) / 100 }}
                  transition={{ duration: 1.5, ease: "easeOut" }}
                  cx="80" cy="80" r="70" stroke="currentColor" strokeWidth="8" fill="transparent" 
                  strokeDasharray="440"
                  strokeLinecap="round"
                  className={auditScore < 70 ? 'text-rose-500' : 'text-emerald-400'} 
                />
              </svg>
              <div className="absolute flex flex-col items-center">
                <span className={`text-4xl font-bold tracking-tighter ${auditScore < 70 ? 'text-rose-500' : 'text-emerald-400'}`}>
                  {auditScore}%
                </span>
              </div>
            </div>

            <button 
              onClick={triggerAudit}
              className="w-full py-3.5 bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-500/25 transition-all font-medium rounded-xl flex items-center justify-center gap-2 active:scale-95"
            >
              <ShieldAlert size={18} />
              Run Deep Audit
            </button>
          </div>

          {/* AI Models Status */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 flex-1 flex flex-col overflow-hidden">
            <h3 className="text-sm font-semibold text-slate-200 mb-6 flex items-center gap-2 shrink-0">
              <Cpu size={18} className="text-indigo-400" />
              AI Agent Status
            </h3>
            
            <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar space-y-4">
              {[
                { name: "Network Packet Model", status: "Active", bg: "bg-emerald-500/20", text: "text-emerald-400", dot: "bg-emerald-500" },
                { name: "Kernel Memory Model", status: "Active", bg: "bg-emerald-500/20", text: "text-emerald-400", dot: "bg-emerald-500" },
                { name: "Web Heuristics Model", status: "Active", bg: "bg-emerald-500/20", text: "text-emerald-400", dot: "bg-emerald-500" },
                { name: "Windows Log Model", status: "Standby", bg: "bg-slate-800", text: "text-slate-400", dot: "bg-slate-500" },
                { name: "Audit Compliance Model", status: "Ready", bg: "bg-blue-500/20", text: "text-blue-400", dot: "bg-blue-500" }
              ].map((agent, i) => (
                <div key={i} className="flex flex-col p-4 rounded-xl border border-slate-800 bg-slate-950/50">
                  <div className="flex justify-between items-center mb-2">
                    <span className="font-medium text-sm text-slate-200">{agent.name}</span>
                    <span className={`px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider ${agent.bg} ${agent.text} flex items-center gap-1.5`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${agent.dot}`} />
                      {agent.status}
                    </span>
                  </div>
                  <div className="text-xs text-slate-500">Node ID: AGT-{2048 + i}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* NODE MODAL (Full Screen Overlay) */}
      <AnimatePresence>
        {selectedNode && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4 sm:p-8"
          >
            <motion.div 
              initial={{ scale: 0.95, opacity: 0, y: 20 }}
              animate={{ scale: 1, opacity: 1, y: 0 }}
              exit={{ scale: 0.95, opacity: 0, y: 20 }}
              transition={{ type: "spring", damping: 25, stiffness: 300 }}
              className="bg-slate-900 border border-slate-700 shadow-2xl shadow-black/50 w-full max-w-5xl h-[700px] rounded-2xl flex flex-col overflow-hidden"
            >
              {/* Modal Header */}
              <div className="px-8 py-5 border-b border-slate-800 flex justify-between items-center bg-slate-950/50">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
                    <Search size={20} />
                  </div>
                  <div>
                    <h2 className="text-lg font-bold text-slate-100">{selectedNode.id}</h2>
                    <p className="text-xs text-slate-400 font-mono">Detailed Telemetry View</p>
                  </div>
                </div>
                <button 
                  onClick={() => setSelectedNode(null)}
                  className="p-2 text-slate-400 hover:bg-slate-800 hover:text-white rounded-lg transition-colors"
                >
                  <X size={24} />
                </button>
              </div>

              {/* Modal Body */}
              <div className="flex-1 grid grid-cols-1 lg:grid-cols-[300px_1fr] p-8 gap-8 min-h-0 bg-slate-950/20">
                
                {/* Specs Sidebar */}
                <div className="flex flex-col gap-6">
                  <div className="bg-slate-900 rounded-xl border border-slate-800 p-6 flex-1 relative overflow-hidden">
                    {selectedNode.isInfected && (
                      <div className="absolute inset-0 bg-rose-500/5 border-2 border-rose-500/50 animate-pulse rounded-xl pointer-events-none" />
                    )}
                    
                    <h3 className="text-sm font-semibold text-slate-200 mb-6 flex items-center gap-2">
                       <HardDrive size={16} className="text-slate-400"/> Hardware Profile
                    </h3>

                    <div className="space-y-5">
                      <div>
                        <div className="text-xs text-slate-500 mb-1">IP Address</div>
                        <div className="text-sm font-mono text-slate-200 bg-slate-950 px-3 py-2 rounded-md border border-slate-800">{selectedNode.ip}</div>
                      </div>
                      <div>
                        <div className="text-xs text-slate-500 mb-1">MAC Address</div>
                        <div className="text-sm font-mono text-slate-200 bg-slate-950 px-3 py-2 rounded-md border border-slate-800">{selectedNode.mac}</div>
                      </div>
                      <div>
                        <div className="text-xs text-slate-500 mb-1">Operating System</div>
                        <div className="text-sm font-medium text-slate-200">{selectedNode.os}</div>
                      </div>
                      
                      <div className="pt-4 border-t border-slate-800">
                         <div className="flex justify-between items-end mb-2">
                           <span className="text-xs text-slate-500">Memory Usage</span>
                           <span className="text-sm font-bold text-slate-200">{selectedNode.ram} GB</span>
                         </div>
                         <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                           <div className="bg-blue-500 h-full rounded-full" style={{ width: `${(selectedNode.ram/16)*100}%` }} />
                         </div>
                      </div>
                      
                      <div>
                         <div className="flex justify-between items-end mb-2">
                           <span className="text-xs text-slate-500">CPU Load</span>
                           <span className="text-sm font-bold text-slate-200">{selectedNode.cpu}%</span>
                         </div>
                         <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                           <div className={`h-full rounded-full ${selectedNode.cpu > 80 ? 'bg-rose-500' : 'bg-indigo-500'}`} style={{ width: `${selectedNode.cpu}%` }} />
                         </div>
                      </div>
                    </div>
                  </div>

                  <button 
                    onClick={handleIsolate}
                    className="w-full py-4 bg-rose-500/10 hover:bg-rose-600 text-rose-500 hover:text-white border border-rose-500/50 shadow-lg hover:shadow-rose-500/25 transition-all text-sm font-bold rounded-xl flex items-center justify-center gap-2"
                  >
                    <ShieldAlert size={18} /> Isolate Workstation
                  </button>
                </div>

                {/* Sub-Terminal Log */}
                <div className="bg-[#0c0c14] border border-slate-800 rounded-xl flex flex-col overflow-hidden shadow-inner">
                  <div className="px-6 py-3 border-b border-slate-800 flex items-center gap-2 bg-[#12121a]">
                    <div className="w-2.5 h-2.5 rounded-full bg-slate-600" />
                    <div className="w-2.5 h-2.5 rounded-full bg-slate-600" />
                    <div className="w-2.5 h-2.5 rounded-full bg-slate-600" />
                    <span className="ml-4 text-xs font-mono text-slate-500">host@telemetry_stream ~</span>
                  </div>
                  <div className="flex-1 p-6 font-mono text-sm space-y-3">
                    <div className="text-slate-400">
                      <span className="text-indigo-400">INIT</span> Establishing secure RPC sidechannel to {selectedNode.ip}...
                    </div>
                    <div className="text-emerald-400">
                      <span className="text-indigo-400">NET</span> Port sweep negative. TCP stack nominal.
                    </div>
                    <div className="text-emerald-400">
                      <span className="text-indigo-400">MEM</span> Kernel RAM heuristics scanned. No fileless signatures found.
                    </div>
                    <div className="text-slate-400">
                      <span className="text-indigo-400">LOG</span> EVTX stream attached. Waiting for generic Audit trigger.
                    </div>
                    
                    {selectedNode.isInfected && (
                      <motion.div 
                        initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                        className="text-rose-400 mt-6 !mt-8 p-3 border border-rose-500/30 bg-rose-500/10 rounded"
                      >
                        <span className="font-bold">CRITICAL:</span> Anomalous payload detected in svchost.exe memory space. Recommend immediate isolation.
                      </motion.div>
                    )}
                    
                    <div className="text-slate-500 animate-pulse mt-4">_</div>
                  </div>
                </div>

              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
      
    </div>
  );
}
