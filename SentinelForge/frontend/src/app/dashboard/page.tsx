"use client";

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { io, Socket } from 'socket.io-client';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  ShieldAlert, Activity, Cpu, Server, 
  Zap, FileCheck, ShieldCheck, Database,
  AlertTriangle, Wifi
} from 'lucide-react';

interface Threat {
  id: string;
  type: string;
  severity: string;
  probability: number;
}

interface ResourceMetrics {
  cpu: number;
  ram: number;
  disk: number;
}

export default function Dashboard() {
  const router = useRouter();
  const [socket, setSocket] = useState<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [resources, setResources] = useState<ResourceMetrics>({ cpu: 0, ram: 0, disk: 0 });

  useEffect(() => {
    // Verify JWT token exists
    const token = localStorage.getItem('sentinelforge_token');
    if (!token) {
      router.push('/login');
      return;
    }

    // Connect to Python Socket.io server securely
    const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000';
    const newSocket = io(backendUrl, {
      transports: ['websocket'],
      auth: { token }
    });

    newSocket.on('connect', () => {
      setIsConnected(true);
      newSocket.emit('dashboard_join', { role: 'admin' });
    });

    newSocket.on('connect_error', (err) => {
        if (err.message === "Authentication failed") {
             localStorage.removeItem('sentinelforge_token');
             router.push('/login');
        }
    });

    newSocket.on('disconnect', () => {
      setIsConnected(false);
    });

    newSocket.on('new_threat_alert', (threat: Threat) => {
      setThreats(prev => [threat, ...prev].slice(0, 10)); // Keep last 10
    });

    newSocket.on('resource_update', (metrics: ResourceMetrics) => {
      setResources(metrics);
    });

    setSocket(newSocket);

    return () => {
      newSocket.disconnect();
    };
  }, [router]);

  const simulatePacket = () => {
    if (socket) {
      socket.emit('simulate_packet', { 
        packet: {
          packet_id: `pkt_${Math.random().toString(36).substring(7)}`,
          source_ip: "192.168.1.100",
          dest_ip: "10.0.0.5",
          protocol: "TCP",
          size: Math.floor(Math.random() * 2000)
        }
      });
    }
  };

  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-100 p-6 selection:bg-cyan-500/30">
      
      {/* Header */}
      <header className="flex justify-between items-center mb-8 bg-neutral-900/50 p-4 rounded-2xl border border-neutral-800 backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-gradient-to-tr from-cyan-600 to-blue-700 rounded-lg shadow-lg shadow-cyan-500/20">
            <ShieldCheck className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-cyan-400 to-blue-400">SentinelForge</h1>
            <p className="text-xs text-neutral-400 font-mono">Agentic Orchestration Active</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 bg-neutral-900 px-3 py-1.5 rounded-full border border-neutral-800">
            <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)] animate-pulse' : 'bg-rose-500'}`} />
            <span className="text-xs font-medium text-neutral-300">
              {isConnected ? 'Socket Connected' : 'Disconnected'}
            </span>
          </div>
          <button 
            onClick={simulatePacket}
            className="text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 px-4 py-2 rounded-lg hover:bg-cyan-500/20 transition-colors"
          >
            Simulate Attack Packet
          </button>
        </div>
      </header>

      {/* Grid Layout */}
      <div className="grid grid-cols-12 gap-6">
        
        {/* Left Column: Systems & Compliance */}
        <div className="col-span-12 lg:col-span-3 flex flex-col gap-6">
          {/* Systems Module */}
          <section className="bg-neutral-900/50 rounded-2xl border border-neutral-800 p-5 flex-1 relative overflow-hidden group">
            <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
            <div className="flex items-center gap-2 mb-4">
              <Server className="w-5 h-5 text-blue-400" />
              <h2 className="font-semibold tracking-wide">Systems</h2>
            </div>
            <div className="space-y-4">
              <div className="p-3 bg-neutral-900 rounded-xl border border-neutral-800/50">
                <div className="text-xs text-neutral-500 mb-1">Monitored Nodes</div>
                <div className="text-2xl font-bold text-neutral-200">24</div>
              </div>
              <div className="p-3 bg-neutral-900 rounded-xl border border-neutral-800/50">
                <div className="text-xs text-neutral-500 mb-1">Real-time Activities</div>
                <div className="text-sm text-neutral-300 font-mono">Normal Operations</div>
              </div>
            </div>
          </section>

          {/* Compliance Module */}
          <section className="bg-neutral-900/50 rounded-2xl border border-neutral-800 p-5 flex-1 relative overflow-hidden group">
             <div className="absolute inset-0 bg-gradient-to-br from-emerald-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
            <div className="flex items-center gap-2 mb-4">
              <FileCheck className="w-5 h-5 text-emerald-400" />
              <h2 className="font-semibold tracking-wide">Compliance</h2>
            </div>
            <div className="flex items-center justify-center py-4">
               <div className="relative flex items-center justify-center">
                  <svg className="w-24 h-24 transform -rotate-90">
                    <circle cx="48" cy="48" r="36" stroke="currentColor" strokeWidth="8" fill="transparent" className="text-neutral-800" />
                    <circle cx="48" cy="48" r="36" stroke="currentColor" strokeWidth="8" fill="transparent" strokeDasharray="226" strokeDashoffset="22.6" className="text-emerald-500" />
                  </svg>
                  <span className="absolute text-xl font-bold text-emerald-400">90%</span>
               </div>
            </div>
             <p className="text-xs text-center text-neutral-400">Last Audit: Today, 08:00 AM</p>
          </section>
        </div>

        {/* Middle Column: Threats & Power */}
        <div className="col-span-12 lg:col-span-6 flex flex-col gap-6">
          {/* Threats Module (Real-time updates) */}
          <section className="bg-neutral-900/80 rounded-2xl border border-rose-900/30 p-5 flex-[2] flex flex-col relative overflow-hidden">
             <div className="absolute top-0 right-0 w-64 h-64 bg-rose-500/5 rounded-full blur-3xl -mr-20 -mt-20 pointer-events-none" />
            
            <div className="flex items-center justify-between mb-4 relative">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-rose-500" />
                <h2 className="font-semibold text-rose-100 tracking-wide">Active Threats</h2>
              </div>
              {threats.length > 0 && (
                <span className="bg-rose-500/20 text-rose-400 border border-rose-500/20 text-xs px-2 py-1 rounded-full animate-pulse">
                  {threats.length} Detected
                </span>
              )}
            </div>

            <div className="flex-1 overflow-y-auto pr-2 space-y-3 relative">
              {threats.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-neutral-500 gap-2">
                  <ShieldCheck className="w-8 h-8 opacity-50" />
                  <p className="text-sm">No active threats detected.</p>
                </div>
              ) : (
                threats.map((threat, idx) => (
                  <div key={idx} className="bg-rose-950/20 border border-rose-900/50 p-4 rounded-xl flex items-center justify-between hover:bg-rose-950/40 transition-colors">
                    <div className="flex items-start gap-3">
                      <div className="mt-1">
                        <AlertTriangle className="w-4 h-4 text-rose-500" />
                      </div>
                      <div>
                        <h4 className="font-medium text-rose-200 text-sm">{threat.type}</h4>
                        <p className="text-xs text-neutral-400 font-mono mt-1">ID: {threat.id}</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-xs font-semibold text-rose-500 uppercase tracking-wider">{threat.severity}</div>
                      <div className="text-xs text-rose-300 mt-1">{(threat.probability * 100).toFixed(1)}% Confidence</div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </section>

          {/* Power Module */}
          <section className="bg-neutral-900/50 rounded-2xl border border-neutral-800 p-5 flex-1 relative overflow-hidden group">
             <div className="absolute inset-0 bg-gradient-to-br from-amber-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Zap className="w-5 h-5 text-amber-500" />
                <h2 className="font-semibold tracking-wide">Power Stats</h2>
              </div>
              <span className="text-emerald-400 text-sm font-medium">Optimal</span>
            </div>
            
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-neutral-900 p-4 rounded-xl border border-neutral-800/50">
                 <div className="text-xs text-neutral-500 mb-1">Current Draw</div>
                 <div className="text-xl font-bold text-amber-100">1.2 <span className="text-sm font-normal text-neutral-500">kW</span></div>
              </div>
              <div className="bg-neutral-900 p-4 rounded-xl border border-neutral-800/50">
                 <div className="text-xs text-neutral-500 mb-1">Efficiency</div>
                 <div className="text-xl font-bold text-amber-100">94<span className="text-sm font-normal text-neutral-500">%</span></div>
              </div>
            </div>
          </section>
        </div>

        {/* Right Column: Resources */}
        <div className="col-span-12 lg:col-span-3 flex flex-col gap-6">
          <section className="bg-neutral-900/50 rounded-2xl border border-neutral-800 p-5 flex-1 relative overflow-hidden group">
             <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
            <div className="flex items-center gap-2 mb-6">
              <Activity className="w-5 h-5 text-cyan-400" />
              <h2 className="font-semibold tracking-wide">Resources</h2>
            </div>
            
            <div className="space-y-6">
              {/* CPU */}
              <div>
                <div className="flex justify-between text-xs mb-2">
                  <span className="flex items-center gap-1.5 text-neutral-300"><Cpu className="w-3.5 h-3.5"/> CPU</span>
                  <span className="font-mono text-cyan-400">{resources.cpu}%</span>
                </div>
                <div className="h-2 w-full bg-neutral-800 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-cyan-500 transition-all duration-500 ease-out" 
                    style={{width: `${resources.cpu}%`}}
                  />
                </div>
              </div>
              
              {/* RAM */}
              <div>
                <div className="flex justify-between text-xs mb-2">
                  <span className="flex items-center gap-1.5 text-neutral-300"><Database className="w-3.5 h-3.5" /> RAM</span>
                  <span className="font-mono text-cyan-400">{resources.ram}%</span>
                </div>
                <div className="h-2 w-full bg-neutral-800 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-blue-500 transition-all duration-500 ease-out" 
                    style={{width: `${resources.ram}%`}}
                  />
                </div>
              </div>

               {/* Disk */}
               <div>
                <div className="flex justify-between text-xs mb-2">
                  <span className="flex items-center gap-1.5 text-neutral-300"><Server className="w-3.5 h-3.5" /> Disk</span>
                  <span className="font-mono text-cyan-400">{resources.disk}%</span>
                </div>
                <div className="h-2 w-full bg-neutral-800 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-indigo-500 transition-all duration-500 ease-out" 
                    style={{width: `${resources.disk}%`}}
                  />
                </div>
              </div>

               {/* Network mini */}
               <div className="pt-4 mt-2 border-t border-neutral-800/50">
                  <div className="flex items-center gap-2 mb-2">
                    <Wifi className="w-4 h-4 text-neutral-400" />
                    <span className="text-xs text-neutral-400">Network I/O</span>
                  </div>
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-emerald-400">↓ 45 Mb/s</span>
                    <span className="text-blue-400">↑ 12 Mb/s</span>
                  </div>
               </div>
            </div>
          </section>
        </div>

      </div>
    </div>
  );
}
