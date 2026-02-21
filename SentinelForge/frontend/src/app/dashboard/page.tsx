"use client";

import { useEffect, useState, useRef } from "react";
import { useRouter } from "next/navigation";
import { io, Socket } from "socket.io-client";
import { motion, AnimatePresence } from "framer-motion";
import { 
  ShieldAlert, Activity, Cpu, Network, Server, 
  Terminal, ShieldCheck, X, Search, CheckCircle2,
  AlertTriangle, Clock, HardDrive, Sliders, Download
} from "lucide-react";
import { AreaChart, Area, ResponsiveContainer } from "recharts";

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
  isResolving?: boolean;
}

export default function ProfessionalDashboard() {
  const router = useRouter();
  const [socket, setSocket] = useState<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [uptime, setUptime] = useState("00:00:00");
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [activeThreats, setActiveThreats] = useState(0);
  const [auditScore, setAuditScore] = useState(98);
  const [scanMode, setScanMode] = useState<"deep" | "stealth" | "smart">("smart");
  const [auditModalData, setAuditModalData] = useState<any>(null);
  const [nodes, setNodes] = useState<NodeDetail[]>([]);
  const [selectedNode, setSelectedNode] = useState<NodeDetail | null>(null);
  const [localNodeModels, setLocalNodeModels] = useState<Record<string, boolean>>({});
  
  const [cpuLoad, setCpuLoad] = useState(0);
  const [netTraffic, setNetTraffic] = useState(0);
  
  const [showTuning, setShowTuning] = useState(false);
  const [netContamination, setNetContamination] = useState(0.05);
  const [pytorchThreshold, setPytorchThreshold] = useState(0.80);
  
  const [terminalInput, setTerminalInput] = useState("");
  
  // Historical data for Sparklines
  const [cpuHistory, setCpuHistory] = useState<{val: number}[]>(Array(20).fill({val: 0}));
  const [netHistory, setNetHistory] = useState<{val: number}[]>(Array(20).fill({val: 0}));
  const [threatHistory, setThreatHistory] = useState<{val: number}[]>(Array(20).fill({val: 0}));
  const [nodesHistory, setNodesHistory] = useState<{val: number}[]>(Array(20).fill({val: 12}));

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
    
    // Fetch initial AI Configs
    fetch(`${backendUrl}/api/agents/config`, { headers: { "Authorization": `Bearer ${token}` } })
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data)) {
          data.forEach(c => {
             if (c.agent_name === "NET" && c.parameter === "contamination") setNetContamination(c.value);
             if (c.agent_name === "NET" && c.parameter === "threat_threshold") setPytorchThreshold(c.value);
          });
        }
      })
      .catch(err => console.error("Failed to fetch configs", err));

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
        setActiveThreats(prev => {
          const newVal = prev + 1;
          setThreatHistory(h => [...h, {val: newVal}].slice(-20));
          return newVal;
        });
        setNodes(prev => {
          const newNodes = [...prev];
          const randomIdx = Math.floor(Math.random() * newNodes.length);
          newNodes[randomIdx].isInfected = true;
          return newNodes;
        });
        addLog(data.model || "Network", `Threat Detected: ${data.detail}`, "error");
      } else if (data.type === "AUDIT_RESULT") {
        setAuditScore(data.score);
        if (data.report_json) {
           try {
              setAuditModalData(JSON.parse(data.report_json));
           } catch(e) {}
        }
        addLog("Audit", `Compliance scan completed. Score: ${data.score}%`, data.score < 70 ? "warn" : "success");
      } else if (data.type === "HEARTBEAT") {
        setCpuLoad(data.cpu);
        setCpuHistory(prev => [...prev, {val: data.cpu}].slice(-20));
        
        setNetTraffic(data.net_mbps);
        setNetHistory(prev => [...prev, {val: data.net_mbps}].slice(-20));
        
        // Push stable histories just to keep graphs scrolling
        setThreatHistory(prev => [...prev, {val: prev[prev.length - 1]?.val || 0}].slice(-20));
        setNodesHistory(prev => [...prev, {val: nodes.length}].slice(-20));
        
      } else if (data.type === "SUPERVISOR") {
        addLog(data.model || "SOC_LLM", `🔥 ${data.detail}`, "warn");
      } else if (data.type === "RESOLUTION_SUCCESS") {
        setNodes(prev => prev.map(n => n.id === data.node_id ? { ...n, isInfected: false, isResolving: false } : n));
        setActiveThreats(prev => {
          const newVal = Math.max(0, prev - 1);
          setThreatHistory(h => [...h, {val: newVal}].slice(-20));
          return newVal;
        });
        addLog("Admin", `Threat on ${data.node_id} was successfully resolved. Unit returned to Active Duty.`, "success");
        if (selectedNode?.id === data.node_id) {
            setSelectedNode(null);
        }
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

  // Phase 23: Doomsday Protocol — auto-detect mass infection and hard reset
  useEffect(() => {
    if (nodes.length === 0) return;
    const infectedCount = nodes.filter(n => n.isInfected).length;
    const infectionRate = infectedCount / nodes.length;

    if (infectionRate >= 0.8) {
      addLog("DOOMSDAY", `⚠ CRITICAL: ${infectedCount}/${nodes.length} endpoints compromised (${Math.round(infectionRate * 100)}%). Initiating Doomsday Protocol — HARD RESET on all systems.`, "error");

      // Hard reset every node
      setNodes(prev => prev.map(n => ({ ...n, isInfected: false, isResolving: false })));
      setActiveThreats(0);

      // Notify backend to mass-quarantine
      if (socket) {
        nodes.filter(n => n.isInfected).forEach(n => {
          socket.emit("trigger_audit", { scanType: "deep", nodeId: n.id });
        });

        // Force reconnect the socket so backend data stream resumes
        addLog("DOOMSDAY", "Reconnecting to backend telemetry stream...", "warn");
        socket.disconnect();
        setTimeout(() => {
          socket.connect();
          addLog("DOOMSDAY", "Backend connection re-established. Data stream active.", "success");
        }, 2000);
      }

      addLog("DOOMSDAY", "Hard reset complete. All endpoints restored to nominal state. Recommend full forensic sweep.", "success");
    }
  }, [nodes]);

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
    addLog("Admin", `Manual Audit Initiated (${scanMode.toUpperCase()}). Waking Log Model...`, "warn");
    if (socket) socket.emit("trigger_audit", { scanType: scanMode });
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

  const handleResolve = async () => {
    if (!selectedNode) return;
    
    // Set UI to resolving state locally
    setNodes(prev => prev.map(n => n.id === selectedNode.id ? { ...n, isResolving: true } : n));
    setSelectedNode(prev => prev ? { ...prev, isResolving: true } : null);
    addLog("Admin", `Initiated Autonomous Resolution sequence for ${selectedNode.id}`, "warn");

    try {
      const token = localStorage.getItem("token");
      const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";
      
      await fetch(`${backendUrl}/api/resolve/${selectedNode.id}`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${token}` }
      });
      // The backend will fire a RESOLUTION_SUCCESS websocket event when it finishes
    } catch (err) {
      addLog("System", `Failed to trigger resolution on ${selectedNode.id}`, "error");
      setNodes(prev => prev.map(n => n.id === selectedNode.id ? { ...n, isResolving: false } : n));
      setSelectedNode(prev => prev ? { ...prev, isResolving: false } : null);
    }
  };

  useEffect(() => {
    if (selectedNode) {
      const fetchModels = async () => {
        try {
          const token = localStorage.getItem("token");
          const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";
          const res = await fetch(`${backendUrl}/api/nodes/${selectedNode.id}/models`, {
            headers: { "Authorization": `Bearer ${token}` }
          });
          if (res.ok) {
            const data = await res.json();
            setLocalNodeModels(data.models || {});
          }
        } catch (err) {}
      };
      fetchModels();
    }
  }, [selectedNode]);

  const toggleNodeModel = async (modelName: string, currentState: boolean) => {
    if (!selectedNode) return;
    const newState = !currentState;
    setLocalNodeModels(prev => ({ ...prev, [modelName]: newState })); // Optimistic update
    try {
      const token = localStorage.getItem("token");
      const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";
      const res = await fetch(`${backendUrl}/api/nodes/${selectedNode.id}/models/${modelName}/toggle`, {
        method: "POST",
        headers: { 
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ is_active: newState })
      });
      if (!res.ok) throw new Error("Toggle failed");
      addLog("Admin", `Toggled ${modelName} on ${selectedNode.id} to ${newState ? "ON" : "OFF"}`, "success");
    } catch (err) {
      addLog("System", "Failed to toggle model.", "error");
      setLocalNodeModels(prev => ({ ...prev, [modelName]: currentState })); // Revert on fail
    }
  };

  const updateAIConfig = async (agent: string, param: string, value: number) => {
    try {
      const token = localStorage.getItem("token");
      const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";
      
      await fetch(`${backendUrl}/api/agents/config/${agent}`, {
        method: "POST",
        headers: { 
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ parameter: param, value: value })
      });
      addLog("Admin", `Updated ${agent} ${param} to ${value}`, "success");
    } catch (err) {
      addLog("System", `Failed to update ${agent} config`, "error");
    }
  };

  const handleDownloadReport = async () => {
    try {
      addLog("Admin", "Requesting generated Excel Threat Report from central server...", "info");
      const token = localStorage.getItem("token");
      const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";
      
      const res = await fetch(`${backendUrl}/api/export/report`, {
        method: "GET",
        headers: { "Authorization": `Bearer ${token}` }
      });
      
      if (!res.ok) throw new Error("Export failed");
      
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "SentinelForge_Threat_Report.xlsx";
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      addLog("System", "Excel Report downloaded successfully.", "success");
    } catch (err) {
      addLog("System", "Failed to download Excel report.", "error");
    }
  };

  const handleTerminalSubmit = async (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && terminalInput.trim()) {
      const command = terminalInput;
      addLog("Admin", `> ${command}`, "warn");
      setTerminalInput("");
      
      try {
        const sessionKeyB64 = localStorage.getItem("session_key");
        if (sessionKeyB64 && socket) {
           // Decrypt the base64 key back to ArrayBuffer then import crypto key
           const binaryString = window.atob(sessionKeyB64);
           const bytes = new Uint8Array(binaryString.length);
           for (let i = 0; i < binaryString.length; i++) {
               bytes[i] = binaryString.charCodeAt(i);
           }
           
           const cryptoKey = await window.crypto.subtle.importKey(
               "raw",
               bytes,
               { name: "AES-GCM" },
               false,
               ["encrypt"]
           );
           
           const iv = window.crypto.getRandomValues(new Uint8Array(12));
           const encodedCommand = new TextEncoder().encode(command);
           
           const encryptedBuffer = await window.crypto.subtle.encrypt(
               { name: "AES-GCM", iv: iv },
               cryptoKey,
               encodedCommand
           );
           
           // Convert IV and Cyphertext to Base64
           const ivB64 = window.btoa(String.fromCharCode(...new Uint8Array(iv)));
           const cipherB64 = window.btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer)));
           
           socket.emit("agent_command", { cipherText: cipherB64, iv: ivB64 });
        } else if (socket) {
           // Fallback if no session key (development)
           socket.emit("agent_command", { command: command });
        }
      } catch (err) {
        addLog("System", "Failed to construct E2E encrypted tunnel.", "error");
        console.error(err);
      }
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
          <button 
             onClick={handleDownloadReport}
             className="flex items-center gap-2 text-sm text-indigo-400 hover:text-indigo-300 font-medium transition-all active:scale-95"
          >
             <Download size={16} /> <span>Export Report</span>
          </button>
          
          <div className="h-4 w-px bg-slate-800" />
          
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
          
          {/* KPI Stat Cards with Realtime Sparkline Graphs */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-6 shrink-0 z-10">
            {[
              { title: "Monitored Endpoints", value: nodes.length, icon: Server, color: "text-blue-400", bg: "bg-blue-500/10", data: nodesHistory, fill: "#3b82f6" },
              { title: "Avg Network Traffic", value: `${netTraffic} Mbps`, icon: Activity, color: "text-indigo-400", bg: "bg-indigo-500/10", data: netHistory, fill: "#6366f1" },
              { title: "Avg CPU Load", value: `${cpuLoad}%`, icon: Cpu, color: "text-violet-400", bg: "bg-violet-500/10", data: cpuHistory, fill: "#8b5cf6" },
              { title: "Active Security Threats", value: activeThreats, icon: AlertTriangle, color: "text-rose-400", bg: "bg-rose-500/10", isDanger: activeThreats > 0, data: threatHistory, fill: "#f43f5e" }
            ].map((stat, i) => (
              <div key={i} className={`glass-panel p-6 flex flex-col relative overflow-hidden transition-colors h-[150px] ${stat.isDanger ? 'border-pulse-red bg-rose-950/20' : ''}`}>
                
                {/* Background Glow Injector */}
                <div className={`absolute top-0 right-0 w-32 h-32 rounded-full blur-3xl opacity-20 ${stat.bg}`}></div>

                {/* Background Recharts Area */}
                <div className="absolute inset-0 top-14 opacity-50 pointer-events-none drop-shadow-[0_0_8px_rgba(255,255,255,0.5)]">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={stat.data}>
                      <Area 
                        type="monotone" 
                        dataKey="val" 
                        stroke={stat.fill} 
                        fill={`url(#gradient-${i})`} 
                        strokeWidth={3}
                        isAnimationActive={false} 
                      />
                      <defs>
                        <linearGradient id={`gradient-${i}`} x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor={stat.fill} stopOpacity={0.3}/>
                          <stop offset="95%" stopColor={stat.fill} stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                    </AreaChart>
                  </ResponsiveContainer>
                </div>

                <div className="flex justify-between items-start mb-2 relative z-10">
                  <span className="text-sm font-medium text-slate-300 tracking-wider font-mono">{stat.title}</span>
                  <div className={`p-2 rounded-lg ${stat.bg} ${stat.color} shadow-lg backdrop-blur-sm ring-1 ring-white/10`}>
                    <stat.icon size={18} />
                  </div>
                </div>
                <div className={`text-4xl font-bold font-sans tracking-tight mt-auto relative z-10 drop-shadow-lg ${stat.isDanger ? 'text-glow-red text-white' : 'text-glow-blue text-white'}`}>
                  {stat.value}
                </div>
              </div>
            ))}
          </div>

          {/* System Nodes Grid */}
          <div className="glass-panel flex flex-col p-6 flex-1 min-h-0 shrink-0 z-10">
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-base font-semibold text-slate-200 flex items-center gap-2">
                <Network size={18} className="text-blue-400" />
                Active Workstation Grid
              </h2>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-5 overflow-y-auto custom-scrollbar pr-2 pb-2 min-h-0">
              {nodes.map((node, i) => (
                <motion.div 
                  key={node.id}
                  whileHover={{ scale: 1.04, y: -4 }}
                  onClick={() => setSelectedNode(node)}
                  style={{ animationDelay: `${i * 0.15}s` }}
                  className={`p-4 rounded-xl border cursor-pointer transition-colors duration-300 flex flex-col gap-2 ${
                    node.isInfected 
                      ? "node-pulse-red bg-rose-950/30" 
                      : "node-pulse-green bg-slate-950/50 hover:bg-slate-900/80"
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
          <div className="glass-panel flex flex-col flex-1 min-h-0 overflow-hidden mt-6">
            <div className="px-6 py-4 border-b border-white/5 flex justify-between items-center bg-black/20">
              <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                <Terminal size={18} className="text-slate-400" />
                Agentic Stream Output
              </h2>
              <button 
                onClick={() => setLogs([])}
                className="text-xs font-medium px-3 py-1.5 rounded bg-slate-800 text-slate-400 hover:text-white hover:bg-slate-700 active:scale-95 transition-all"
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
            
            {/* Interactive CLI Input */}
            <div className="px-6 py-4 bg-black/40 border-t border-white/5 flex items-center gap-3 shrink-0 focus-within:ring-1 focus-within:ring-indigo-500/50 transition-all">
               <span className="text-emerald-400 font-mono font-bold text-sm">{">"}</span>
               <input 
                  type="text" 
                  value={terminalInput}
                  onChange={(e) => setTerminalInput(e.target.value)}
                  onKeyDown={handleTerminalSubmit}
                  placeholder="Type /help or chat with SOC LLM Supervisor..."
                  className="bg-transparent border-none outline-none text-slate-200 font-mono text-sm w-full placeholder:text-slate-600 focus:ring-0"
               />
            </div>
          </div>

        </div>

        {/* Right Sidebar - Compliance & Agents */}
        <div className="flex flex-col gap-8 min-h-0">
          
          {/* Security Audit Score */}
          <div className="glass-panel p-8 flex flex-col items-center justify-center relative overflow-hidden shrink-0 mt-[1.5rem]">
            <div className="absolute inset-0 bg-gradient-to-br from-emerald-500/10 to-indigo-500/5 pointer-events-none" />
            
            <h3 className="text-sm font-medium text-slate-400 uppercase tracking-widest mb-6 w-full text-center">
              Security Compliance
            </h3>
            
            <div className="relative flex items-center justify-center mb-8">
              {/* Fake circular gauge background */}
              <svg className="w-40 h-40 transform -rotate-90 drop-shadow-[0_0_15px_rgba(16,185,129,0.3)]">
                <circle cx="80" cy="80" r="70" stroke="rgba(255,255,255,0.05)" strokeWidth="8" fill="transparent" />
                <motion.circle 
                  initial={{ strokeDashoffset: 440 }}
                  animate={{ strokeDashoffset: 440 - (440 * auditScore) / 100 }}
                  transition={{ duration: 2, ease: "easeOut" }}
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

            <div className="w-full flex flex-col gap-3">
              <div className="flex bg-black/30 p-1 rounded-lg border border-white/5 mt-2">
                 <button 
                    onClick={() => setScanMode("deep")}
                    className={`flex-1 text-xs py-1.5 rounded-md font-medium transition-colors ${scanMode === "deep" ? "bg-indigo-500/80 text-white shadow-[0_0_10px_rgba(99,102,241,0.5)]" : "text-slate-400 hover:text-slate-200"}`}
                 >
                    DEEP
                 </button>
                 <button 
                    onClick={() => setScanMode("stealth")}
                    className={`flex-1 text-xs py-1.5 rounded-md font-medium transition-colors ${scanMode === "stealth" ? "bg-indigo-500/80 text-white shadow-[0_0_10px_rgba(99,102,241,0.5)]" : "text-slate-400 hover:text-slate-200"}`}
                 >
                    STEALTH
                 </button>
                 <button 
                    onClick={() => setScanMode("smart")}
                    className={`flex-1 text-xs py-1.5 rounded-md font-medium transition-colors ${scanMode === "smart" ? "bg-indigo-500/80 text-white shadow-[0_0_10px_rgba(99,102,241,0.5)]" : "text-slate-400 hover:text-slate-200"}`}
                 >
                    SMART
                 </button>
              </div>
              <button 
                onClick={triggerAudit}
                className="w-full py-3.5 bg-indigo-600/80 backdrop-blur hover:bg-indigo-500 text-white shadow-[0_0_20px_rgba(99,102,241,0.4)] transition-all font-medium rounded-xl flex items-center justify-center gap-2 active:scale-95 border border-indigo-500/50"
              >
                <ShieldAlert size={18} />
                Run {scanMode.charAt(0).toUpperCase() + scanMode.slice(1)} Audit
              </button>
              {auditModalData && (
                 <button onClick={() => setAuditModalData({...auditModalData})} className="text-xs text-indigo-400 hover:text-indigo-300 underline underline-offset-2 mt-1 w-full text-center">
                    View Last Report
                 </button>
              )}
            </div>
          </div>

          {/* AI Models Status */}
          <div className="glass-panel p-6 flex-1 flex flex-col overflow-hidden">
            <h3 className="text-sm font-semibold text-slate-200 mb-6 flex items-center justify-between shrink-0">
              <div className="flex items-center gap-2">
                <Cpu size={18} className="text-indigo-400" />
                AI Agent Status
              </div>
              <button 
                onClick={() => setShowTuning(true)}
                className="p-1.5 bg-slate-800 hover:bg-slate-700 rounded-md transition-colors text-slate-400 hover:text-white"
                title="Tune AI Models"
              >
                <Sliders size={16} />
              </button>
            </h3>
            
            <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar space-y-4">
              {[
                { name: "Network Packet Model", status: "Active", bg: "bg-emerald-500/20", text: "text-emerald-400", dot: "bg-emerald-500" },
                { name: "Kernel Memory Model", status: "Active", bg: "bg-emerald-500/20", text: "text-emerald-400", dot: "bg-emerald-500" },
                { name: "Web Heuristics Model", status: "Active", bg: "bg-emerald-500/20", text: "text-emerald-400", dot: "bg-emerald-500" },
                { name: "Windows Log Model", status: "Active", bg: "bg-emerald-500/20", text: "text-emerald-400", dot: "bg-emerald-500" },
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
            className="fixed inset-0 bg-slate-950/90 backdrop-blur-md z-50 flex items-center justify-center p-4 sm:p-8"
          >
            <motion.div 
              initial={{ scale: 0.95, opacity: 0, y: 20 }}
              animate={{ scale: 1, opacity: 1, y: 0 }}
              exit={{ scale: 0.95, opacity: 0, y: 20 }}
              transition={{ type: "spring", damping: 25, stiffness: 300 }}
              className="glass-panel w-full max-w-5xl max-h-[85vh] rounded-2xl flex flex-col overflow-hidden shadow-2xl shadow-black/80"
            >
              {/* Modal Header */}
              <div className="px-8 py-5 border-b border-white/5 flex justify-between items-center bg-black/30 shrink-0">
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
                  className="p-2 text-slate-400 hover:bg-white/10 hover:text-white rounded-lg transition-colors"
                >
                  <X size={24} />
                </button>
              </div>

              {/* Modal Body */}
              <div className="flex-1 grid grid-cols-1 lg:grid-cols-[320px_1fr] p-8 gap-8 min-h-0 overflow-hidden">
                
                {/* Specs Sidebar - Scrollable */}
                <div className="flex flex-col gap-6 overflow-y-auto custom-scrollbar pr-2 min-h-0">
                  <div className="glass-panel p-6 relative overflow-hidden shrink-0">
                    {selectedNode.isInfected && (
                      <div className="absolute inset-0 bg-rose-500/5 border-2 border-rose-500/50 animate-pulse rounded-xl pointer-events-none" />
                    )}
                    
                    <h3 className="text-sm font-semibold text-slate-200 mb-6 flex items-center gap-2">
                       <HardDrive size={16} className="text-slate-400"/> Hardware Profile
                    </h3>

                    <div className="space-y-4">
                      <div className="pb-3 border-b border-white/5">
                        <div className="text-xs text-slate-500 mb-1">IP Address</div>
                        <div className="text-sm font-mono text-slate-200 bg-black/30 px-3 py-2 rounded-md border border-white/5">{selectedNode.ip}</div>
                      </div>
                      <div className="pb-3 border-b border-white/5">
                        <div className="text-xs text-slate-500 mb-1">MAC Address</div>
                        <div className="text-sm font-mono text-slate-200 bg-black/30 px-3 py-2 rounded-md border border-white/5">{selectedNode.mac}</div>
                      </div>
                      <div className="pb-3 border-b border-white/5">
                        <div className="text-xs text-slate-500 mb-1">Operating System</div>
                        <div className="text-sm font-mono text-slate-200 bg-black/30 px-3 py-2 rounded-md border border-white/5">{selectedNode.os}</div>
                      </div>
                      
                      <div className="pt-2">
                         <div className="flex justify-between items-end mb-2">
                           <span className="text-xs text-slate-500">Memory Usage</span>
                           <span className="text-sm font-bold text-slate-200">{selectedNode.ram} GB</span>
                         </div>
                         <div className="w-full bg-black/30 h-2 rounded-full overflow-hidden">
                           <div className="bg-blue-500 h-full rounded-full shadow-[0_0_8px_rgba(59,130,246,0.5)]" style={{ width: `${(selectedNode.ram/16)*100}%` }} />
                         </div>
                      </div>
                      
                      <div className="pt-2">
                         <div className="flex justify-between items-end mb-2">
                           <span className="text-xs text-slate-500">CPU Load</span>
                           <span className="text-sm font-bold text-slate-200">{selectedNode.cpu}%</span>
                         </div>
                         <div className="w-full bg-black/30 h-2 rounded-full overflow-hidden">
                           <div className={`h-full rounded-full ${selectedNode.cpu > 80 ? 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.5)]' : 'bg-indigo-500 shadow-[0_0_8px_rgba(99,102,241,0.5)]'}`} style={{ width: `${selectedNode.cpu}%` }} />
                         </div>
                      </div>
                    </div>
                  </div>

                  {/* Phase 13: Granular Model Toggling UI */}
                  <div className="glass-panel p-6 relative shrink-0">
                    <h3 className="text-sm font-semibold text-slate-200 mb-6 flex items-center gap-2">
                       <ShieldCheck size={16} className="text-emerald-500"/> Security Modules
                    </h3>
                    
                    <div className="space-y-3">
                      {[
                        { id: 'NET', label: 'Network Analyzer', desc: 'Deep Packet Inspection' },
                        { id: 'MEM', label: 'Memory Scanner', desc: 'Kernel Ram Heuristics' },
                        { id: 'LOG', label: 'Log Parser', desc: 'NLP Event Correlation' },
                        { id: 'WEB', label: 'Web Monitor', desc: 'HTTP Traffic Analysis' },
                      ].map(model => {
                        // Default to ON if no state exists yet
                        const isActive = localNodeModels[model.id] ?? true;
                        
                        return (
                          <div key={model.id} className="flex items-center justify-between p-3 rounded-lg bg-black/20 border border-white/5">
                            <div>
                               <div className="text-sm font-medium text-slate-200">{model.label}</div>
                               <div className="text-xs text-slate-500">{model.desc}</div>
                            </div>
                            <button
                              onClick={() => toggleNodeModel(model.id, isActive)}
                              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 focus:ring-offset-slate-900 ${
                                isActive ? 'bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.4)]' : 'bg-slate-700'
                              }`}
                            >
                              <span
                                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                                  isActive ? 'translate-x-6' : 'translate-x-1'
                                }`}
                              />
                            </button>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Action Buttons - Always visible at bottom */}
                  {selectedNode.isInfected && (
                    <div className="flex gap-4 shrink-0">
                      <button 
                        onClick={handleIsolate}
                        disabled={selectedNode.isResolving}
                        className="flex-1 py-4 bg-black/30 hover:bg-white/5 text-slate-300 border border-white/10 transition-all text-sm font-bold rounded-xl flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed backdrop-blur"
                      >
                        <ShieldAlert size={18} /> Isolate Host
                      </button>
                      <button 
                        onClick={handleResolve}
                        disabled={selectedNode.isResolving}
                        className={`flex-1 py-4 text-white shadow-lg transition-all text-sm font-bold rounded-xl flex items-center justify-center gap-2 ${selectedNode.isResolving ? 'bg-indigo-600/50 cursor-not-allowed' : 'bg-indigo-600/80 hover:bg-indigo-500 shadow-[0_0_20px_rgba(99,102,241,0.4)] border border-indigo-500/50'}`}
                      >
                        {selectedNode.isResolving ? (
                          <><div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Resolving...</>
                        ) : (
                          <><CheckCircle2 size={18} /> Auto-Resolve</>
                        )}
                      </button>
                    </div>
                  )}
                  {!selectedNode.isInfected && (
                    <div className="w-full py-4 bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 text-sm font-bold rounded-xl flex items-center justify-center gap-2 shrink-0 shadow-[0_0_15px_rgba(16,185,129,0.15)]">
                       <CheckCircle2 size={18} /> System Secure
                    </div>
                  )}
                </div>

                {/* Sub-Terminal Log */}
                <div className="bg-black/40 border border-white/5 rounded-xl flex flex-col overflow-hidden shadow-inner backdrop-blur-sm">
                  <div className="px-6 py-3 border-b border-white/5 flex items-center gap-2 bg-black/30 shrink-0">
                    <div className="w-2.5 h-2.5 rounded-full bg-rose-500/60" />
                    <div className="w-2.5 h-2.5 rounded-full bg-amber-500/60" />
                    <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/60" />
                    <span className="ml-4 text-xs font-mono text-slate-500">host@telemetry_stream ~</span>
                  </div>
                  <div className="flex-1 p-6 font-mono text-sm space-y-3 overflow-y-auto custom-scrollbar">
                    <div className="text-slate-400">
                      <span className="text-indigo-400 font-bold">INIT</span> Establishing secure RPC sidechannel to {selectedNode.ip}...
                    </div>
                    <div className="text-emerald-400">
                      <span className="text-indigo-400 font-bold">NET</span> Port sweep negative. TCP stack nominal.
                    </div>
                    <div className="text-emerald-400">
                      <span className="text-indigo-400 font-bold">MEM</span> Kernel RAM heuristics scanned. No fileless signatures found.
                    </div>
                    <div className="text-slate-400">
                      <span className="text-indigo-400 font-bold">LOG</span> EVTX stream attached. Waiting for generic Audit trigger.
                    </div>
                    
                    {selectedNode.isInfected && (
                      <motion.div 
                        initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                        className="text-rose-400 mt-6 p-4 border border-rose-500/30 bg-rose-500/10 rounded-lg shadow-[0_0_15px_rgba(244,63,94,0.15)]"
                      >
                        <span className="font-bold">⚠ CRITICAL:</span> Anomalous payload detected in svchost.exe memory space. Recommend immediate isolation.
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

      {/* AI MODEL TUNING MODAL */}
      <AnimatePresence>
        {showTuning && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-[100] flex items-center justify-center p-4 sm:p-8"
          >
            <motion.div 
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="bg-slate-900 border border-slate-700 shadow-2xl w-full max-w-xl rounded-2xl flex flex-col overflow-hidden"
            >
              <div className="px-6 py-4 border-b border-slate-800 flex justify-between items-center bg-slate-950/50">
                <div className="flex items-center gap-2">
                  <Sliders size={20} className="text-indigo-400" />
                  <h2 className="text-lg font-bold text-slate-100">Live AI Model Tuning</h2>
                </div>
                <button onClick={() => setShowTuning(false)} className="text-slate-400 hover:text-white transition-colors">
                  <X size={24} />
                </button>
              </div>

              <div className="p-8 flex flex-col gap-8">
                
                {/* PyTorch Threshold Slider */}
                <div>
                  <div className="flex justify-between items-end mb-2">
                    <div>
                      <h4 className="text-sm font-bold text-slate-200">PyTorch Threat Probability Threshold</h4>
                      <p className="text-xs text-slate-500">Lowering this will trigger Deep Learning alerts more frequently.</p>
                    </div>
                    <span className="text-indigo-400 font-mono font-bold bg-indigo-500/10 px-2 py-1 rounded">{pytorchThreshold.toFixed(2)}</span>
                  </div>
                  <input 
                    type="range" min="0.1" max="0.99" step="0.01" value={pytorchThreshold}
                    onChange={(e) => {
                      const val = parseFloat(e.target.value);
                      setPytorchThreshold(val);
                      updateAIConfig("NET", "threat_threshold", val);
                    }}
                    className="w-full h-2 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-indigo-500"
                  />
                </div>

                {/* Isolation Forest Contamination Slider */}
                <div>
                  <div className="flex justify-between items-end mb-2">
                    <div>
                      <h4 className="text-sm font-bold text-slate-200">Isolation Forest Contamination Rate</h4>
                      <p className="text-xs text-slate-500">The expected % of anomalous network traffic baseline.</p>
                    </div>
                    <span className="text-emerald-400 font-mono font-bold bg-emerald-500/10 px-2 py-1 rounded">{(netContamination * 100).toFixed(0)}%</span>
                  </div>
                  <input 
                    type="range" min="0.01" max="0.30" step="0.01" value={netContamination}
                    onChange={(e) => {
                      const val = parseFloat(e.target.value);
                      setNetContamination(val);
                      updateAIConfig("NET", "contamination", val);
                    }}
                    className="w-full h-2 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-emerald-500"
                  />
                </div>
                
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
      
      {/* Detailed Audit Report Modal */}
      <AnimatePresence>
        {auditModalData && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm"
          >
             <motion.div 
               initial={{ scale: 0.95, opacity: 0 }}
               animate={{ scale: 1, opacity: 1 }}
               exit={{ scale: 0.95, opacity: 0 }}
               className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl flex flex-col max-h-[85vh]"
             >
                <div className="p-6 border-b border-slate-800 flex justify-between items-center shrink-0 bg-slate-800/20">
                   <div>
                     <h2 className="text-xl font-bold text-white flex items-center gap-2">
                        <ShieldCheck className={auditModalData.compliance_score < 70 ? "text-rose-500" : "text-emerald-400"} />
                        Deep Compliance Report
                     </h2>
                     <p className="text-sm text-slate-400 mt-1">
                        Node: <span className="text-indigo-400 font-mono">{auditModalData.host}</span> | 
                        Scan Mode: <span className="uppercase text-slate-300 ml-1">{auditModalData.scan_mode}</span>
                     </p>
                   </div>
                   <button 
                     onClick={() => setAuditModalData(null)}
                     className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
                   >
                     <X size={20} />
                   </button>
                </div>
                
                <div className="p-6 overflow-y-auto custom-scrollbar flex-1 space-y-6">
                   <div className="grid grid-cols-2 gap-4">
                      <div className="bg-slate-950/50 p-4 border border-slate-800 rounded-xl">
                         <h3 className="text-xs text-slate-500 uppercase font-semibold mb-2 tracking-wider">Overall Score</h3>
                         <div className={`text-3xl font-bold ${auditModalData.compliance_score < 70 ? "text-rose-500" : "text-emerald-400"}`}>
                            {auditModalData.compliance_score}%
                         </div>
                      </div>
                      <div className="bg-slate-950/50 p-4 border border-slate-800 rounded-xl">
                         <h3 className="text-xs text-slate-500 uppercase font-semibold mb-2 tracking-wider">AI Engines</h3>
                         <div className="flex flex-col gap-1 text-sm font-medium">
                            <div className="flex justify-between">
                               <span className="text-slate-400">PyTorch Net:</span>
                               <span className={auditModalData.ai_health.network_pytorch_engine === "ONLINE" ? "text-emerald-400" : "text-rose-500"}>
                                  {auditModalData.ai_health.network_pytorch_engine}
                               </span>
                            </div>
                            <div className="flex justify-between">
                               <span className="text-slate-400">HyMem Mem:</span>
                               <span className={auditModalData.ai_health.memory_hymem_engine === "ONLINE" ? "text-emerald-400" : "text-rose-500"}>
                                  {auditModalData.ai_health.memory_hymem_engine}
                               </span>
                            </div>
                         </div>
                      </div>
                   </div>
                   
                   {auditModalData.vulnerabilities?.length > 0 ? (
                      <div>
                         <h3 className="text-sm font-semibold text-rose-400 flex items-center gap-2 mb-3">
                            <AlertTriangle size={16} /> Actionable Items Found
                         </h3>
                         <div className="space-y-2">
                            {auditModalData.vulnerabilities.map((v: any, i: number) => (
                               <div key={i} className="bg-rose-500/10 border border-rose-500/20 p-3 rounded-lg flex gap-3 text-sm">
                                  <div className="font-mono text-rose-400 shrink-0">[{v.type}]</div>
                                  <div className="text-slate-300">{v.desc}</div>
                               </div>
                            ))}
                         </div>
                      </div>
                   ) : (
                      <div className="bg-emerald-500/10 border border-emerald-500/20 p-4 rounded-lg flex items-center gap-3 text-emerald-400 text-sm">
                         <CheckCircle2 size={18} />
                         No critical vulnerabilities discovered. Host is compliant.
                      </div>
                   )}
                </div>
             </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
      
    </div>
  );
}
