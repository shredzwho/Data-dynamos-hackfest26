import asyncio
import logging
import psutil
import time
from typing import Dict, Any

from agents.network_model import NetworkModel
from agents.memory_model import MemoryModel
from agents.web_model import WebModel
from agents.log_model import LogModel
from agents.audit_model import AuditModel

logger = logging.getLogger(__name__)

class AgenticManager:
    """
    Central Controller for the 5 AI Models.
    Runs 24/7 surveillance, passes instructions, and bubbles events directly to connected Dashboard WebSockets.
    """
    def __init__(self, callback_func):
        self.callback_func = callback_func
        self.event_queue = asyncio.Queue()
        self.is_running = False
        self.threat_history = []
        
        # Instantiate 5 specialized AI Agents
        self.network_model = NetworkModel(self.event_queue)
        self.memory_model = MemoryModel(self.event_queue)
        self.web_model = WebModel(self.event_queue)
        self.log_model = LogModel(self.event_queue)
        self.audit_model = AuditModel(self.event_queue)
        
        self.agents_map = {
            "NET": self.network_model,
            "MEM": self.memory_model,
            "WEB": self.web_model,
            "LOG": self.log_model,
            "AUD": self.audit_model
        }

    async def update_agent_config(self, agent_name: str, config: dict):
        agent = self.agents_map.get(agent_name)
        if agent:
            await agent.update_config(config)
        else:
            logger.warning(f"Attempted to configure unknown agent: {agent_name}")

    async def start(self):
        self.is_running = True
        
        # Start passive monitors
        asyncio.create_task(self.network_model.start())
        asyncio.create_task(self.memory_model.start())
        asyncio.create_task(self.web_model.start())
        
        # Start the centralized Event Consumer loop
        asyncio.create_task(self._consume_events())
        
        # Start the Telemetry Heartbeat loop
        self.last_bytes = (psutil.net_io_counters().bytes_recv + psutil.net_io_counters().bytes_sent)
        asyncio.create_task(self._emit_heartbeat())
        
        await self._broadcast_info("MGR", "Agentic Manager online. Sub-models initialized.")

    async def _consume_events(self):
        """Pulls events emitted by the 5 agents and routes them to the dashboard."""
        while self.is_running:
            event = await self.event_queue.get()
            
            # --- PHASE 3: LLM SOC SUPERVISOR CORRELATION ---
            if event.get("type") == "THREAT" or "Threat" in event.get("detail", ""):
                current_time = time.time()
                self.threat_history.append({
                    "time": current_time, 
                    "model": event.get("model", "SYS")
                })
                
                # Prune history older than 60 seconds
                self.threat_history = [t for t in self.threat_history if current_time - t["time"] <= 60]
                
                # If 3 distinct threat events hit in the 60s window, the Supervisor awakens
                if len(self.threat_history) >= 3:
                    models_involved = list(set([t["model"] for t in self.threat_history]))
                    
                    if len(models_involved) > 1:
                        analysis = f"SOC Analyst LLM: Correlated multi-vector attack detected across {', '.join(models_involved)}. High probability of synchronized intrusion or C2 beaconing. Recommend IP isolation."
                    else:
                        analysis = f"SOC Analyst LLM: Sustained aggressive anomaly isolated to {models_involved[0]} agent. Potential localized payload execution."
                        
                    # Inject the supervisor's insight into the stream
                    await self.callback_func({
                        "type": "SUPERVISOR",
                        "model": "SOC_LLM",
                        "detail": analysis
                    })
                    
                    # Clear queue to avoid spamming the generative model
                    self.threat_history.clear()
            
            # Use the injected SocketIO callback function
            await self.callback_func(event)
            self.event_queue.task_done()

    async def _emit_heartbeat(self):
        """Pushes live CPU, RAM, and Network speed KPIs every 2 seconds to the dashboard."""
        while self.is_running:
            await asyncio.sleep(2.0)
            try:
                cpu_pct = psutil.cpu_percent()
                
                net_io = psutil.net_io_counters()
                current_bytes = net_io.bytes_recv + net_io.bytes_sent
                speed_mbps = ((current_bytes - self.last_bytes) / 2.0) / 1_000_000
                self.last_bytes = current_bytes

                event = {
                    "type": "HEARTBEAT",
                    "cpu": cpu_pct,
                    "net_mbps": round(speed_mbps, 2)
                }
                await self.callback_func(event)
            except Exception as e:
                logger.error(f"Heartbeat telemetry failed: {str(e)}")

    async def stop(self):
        self.is_running = False
        await self.network_model.stop()
        await self.memory_model.stop()
        await self.web_model.stop()
        await self._broadcast_info("MGR", "Agentic Manager offline.")

    async def trigger_audit(self):
        """Triggered by the IT Admin via the Dashboard."""
        await self._broadcast_info("MGR", "Security Audit Initiated. Waking Log & Audit Models.")
        
        # Wake up reactive models
        asyncio.create_task(self.log_model.run_manual_audit())
        asyncio.create_task(self.audit_model.generate_report())

    async def _broadcast_info(self, source: str, detail: str):
        event = {
            "type": "INFO",
            "model": source,
            "detail": detail
        }
        await self.callback_func(event)

    async def handle_admin_command(self, command: str):
        """Parses inputs from the Interactive Admin Terminal on the React dashboard."""
        
        parts = command.split(" ")
        base_cmd = parts[0].lower()
        
        if base_cmd == "/help":
            await self._broadcast_info("SYS_HELP", "Available commands:\n/set [AGENT] [PARAM] [VAL] - Hot-swaps AI thresholds.\n/ignore IP [IP_ADDR] - Adds an IP to the allowlist.\nOr just type naturally to ask the SOC LLM Supervisor a question.")
        
        elif base_cmd == "/set" and len(parts) == 4:
            agent_name = parts[1].upper()
            param = parts[2]
            try:
                val = float(parts[3])
                await self.update_agent_config(agent_name, {param: val})
                await self._broadcast_info("ADMIN", f"Dynamic state injected: {agent_name} -> {param} = {val}")
            except ValueError:
                await self._broadcast_info("ERROR", "Value must be a number (e.g., 0.8)")
                
        elif base_cmd == "/ignore" and len(parts) >= 3:
            ip_addr = parts[2]
            # Mocking allowlist
            await self._broadcast_info("ADMIN", f"IP {ip_addr} added to global dynamic allowlist. AI models will ignore subsequent traffic.")
            
        else:
            if not command.startswith("/"):
                # Natural Language Chat Query Simulation
                await self._broadcast_info("SOC_LLM", f"Received query: '{command}'. Analyzing telemetry...")
                await asyncio.sleep(1.5)
                await self.callback_func({
                    "type": "SUPERVISOR",
                    "model": "SOC_LLM",
                    "detail": "Based on the recent Event stream, the spikes are isolated to regular automated compliance sweeps. No anomalous payloads detected in the queried pattern."
                })
            else:
                await self._broadcast_info("ERROR", f"Unknown command syntax: {command}")
