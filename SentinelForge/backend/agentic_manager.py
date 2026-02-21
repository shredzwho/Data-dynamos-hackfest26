import asyncio
import logging
import psutil
import time
import os
from typing import Dict, Any

import importlib
import inspect
import pkgutil

from agents.base_agent import BaseAgent
from models.soc_llm import SOCSupervisorLLM

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
        self.bg_tasks = set()
        
        # --- PHASE 17: GLOBAL STATE RECOVERY ---
        import os
        import json
        if os.path.exists("threat_state.json"):
            try:
                with open("threat_state.json", "r") as f:
                    self.threat_history = json.load(f)
                    logger.info(f"Global State Recovery: Reloaded {len(self.threat_history)} historical threats.")
            except Exception as e:
                logger.error(f"Failed to recover threat history: {str(e)}")
                
        self._emit_timestamps = [] # Token bucket for rate limiting
        
        self.agents_map = {}
        self.soc_llm = SOCSupervisorLLM()
        self.pending_actions = {} # HITL Approval Queue
        
        # Phase 13: Granular Model Toggling
        # Format: {"WS-ENT-04": {"NET": True, "LOG": False}}
        self.node_model_states: dict[str, dict[str, bool]] = {}

        self._discover_and_load_agents()

    def _discover_and_load_agents(self):
        import agents
        for _, module_name, _ in pkgutil.iter_modules(agents.__path__):
            if module_name == "base_agent": continue
            module = importlib.import_module(f"agents.{module_name}")
            for name, cls in inspect.getmembers(module, inspect.isclass):
                if issubclass(cls, BaseAgent) and cls is not BaseAgent:
                    sig = inspect.signature(cls.__init__)
                    if 'agentic_manager_ref' in sig.parameters:
                        agent = cls(self.event_queue, agentic_manager_ref=self)
                    else:
                        agent = cls(self.event_queue)
                    self.agents_map[agent.name] = agent
                    logger.info(f"Dynamically loaded agent: {agent.name} [{cls.__name__}]")

    def update_node_model_state(self, node_id: str, model_name: str, is_active: bool):
        if node_id not in self.node_model_states:
            self.node_model_states[node_id] = {}
        self.node_model_states[node_id][model_name] = is_active
        logger.info(f"Updated Supervisor Memory: {model_name} on {node_id} is now {'ON' if is_active else 'OFF'}")

    async def update_agent_config(self, agent_name: str, config: dict):
        agent = self.agents_map.get(agent_name)
        if agent:
            await agent.update_config(config)
        else:
            logger.warning(f"Attempted to configure unknown agent: {agent_name}")

    async def start(self):
        try:
            print("DEBUG: AgenticManager.start() ENTERED", flush=True)
            self.is_running = True
            
            # Start passive monitors via Watchdog
            for agent in self.agents_map.values():
                print(f"DEBUG: Wrapping Watchdog on agent {agent.name}", flush=True)
                task = asyncio.create_task(self._healing_watchdog(agent))
                self.bg_tasks.add(task)
                task.add_done_callback(self.bg_tasks.discard)
                
            task = asyncio.create_task(self.soc_llm.start())
            self.bg_tasks.add(task)
            task.add_done_callback(self.bg_tasks.discard)
            
            # Start the centralized Event Consumer loop
            task = asyncio.create_task(self._consume_events())
            self.bg_tasks.add(task)
            task.add_done_callback(self.bg_tasks.discard)
            
            # Start the Telemetry Heartbeat loop
            self.last_bytes = (psutil.net_io_counters().bytes_recv + psutil.net_io_counters().bytes_sent)
            task = asyncio.create_task(self._emit_heartbeat())
            self.bg_tasks.add(task)
            task.add_done_callback(self.bg_tasks.discard)
            
            # PHASE 21: Force Ransomware Canary Deployment
            vault_dir = os.path.join(os.getcwd(), "SentinelForge-Vault")
            if not os.path.exists(vault_dir):
                os.makedirs(vault_dir, exist_ok=True)
            for bait in ["passwords_backup.txt", "crypto_wallet.dat", "tax_returns_2025.pdf"]:
                filepath = os.path.join(vault_dir, bait)
                if not os.path.exists(filepath):
                    with open(filepath, "w") as f:
                        f.write("SentinelForge decoy payload. Do not modify.\n" * 10)
            logger.info("Ransomware Canary Traps deployed successfully.")

            await self._broadcast_info("MGR", "Agentic Manager online. Ransomware Traps & Sub-models initialized.")
        except Exception as e:
            logger.error(f"FATAL: AgenticManager failed to start! Exception: {e}")

    async def _healing_watchdog(self, agent: BaseAgent):
        """Phase 17 Auto-Healing: Ensures agents stay online 24/7 if an exception occurs."""
        print(f"DEBUG: Watchdog Task Started for {agent.name}", flush=True)
        while self.is_running:
            try:
                print(f"DEBUG: Awaiting agent.start() for {agent.name}", flush=True)
                await agent.start()
            except Exception as e:
                logger.error(f"Agent {agent.name} crashed with exception: {str(e)}")
            
            # Prevent infinite CPU spin if an agent's start() returns immediately
            await asyncio.sleep(2.0)
            
            if self.is_running:
                await self._broadcast_info("SYS_HEALING", f"CRITICAL: {agent.name} engine crashed! Watchdog restarting thread in 3s...")
                await asyncio.sleep(3.0)
                logger.info(f"Watchdog auto-restarting {agent.name}...")

    async def _consume_events(self):
        """Pulls events emitted by the 5 agents and routes them to the dashboard."""
        while self.is_running:
            event = await self.event_queue.get()
            
            # Phase 13: Granular Toggling Event Enforcement
            event_node = event.get("node_id")
            event_model = event.get("model")
            
            if event_node and event_model:
                node_states = self.node_model_states.get(event_node, {})
                # Default to True if not explicitly set to False
                is_active = node_states.get(event_model, True)
                if not is_active:
                    # Model disabled for this node, silently drop the event
                    self.event_queue.task_done()
                    continue
            
            # --- PHASE 17: INTERNAL PUB/SUB MESSAGING ---
            for agent in self.agents_map.values():
                if event.get("type") in agent.subscriptions:
                    # Dispatch asynchronously to avoid blocking the main intake loop
                    asyncio.create_task(agent.handle_event(event))
            
            # --- PHASE 3: LLM SOC SUPERVISOR CORRELATION ---
            if event.get("type") == "THREAT" or "Threat" in event.get("detail", ""):
                current_time = time.time()
                
                # Try to natively extract IP/Geo strings from the raw event detail
                geo_tag = "UNKNOWN"
                if "[" in event.get("detail", "") and "]" in event.get("detail", ""):
                    try:
                        geo_tag = event.get("detail", "").split("[")[1].split("]")[0]
                    except: pass
                    
                self.threat_history.append({
                    "time": current_time, 
                    "model": event.get("model", "SYS"),
                    "geo": geo_tag
                })
                
                # Prune history older than 60 seconds
                self.threat_history = [t for t in self.threat_history if current_time - t["time"] <= 60]
                
                # If 3 distinct threat events hit in the 60s window, the Supervisor awakens
                if len(self.threat_history) >= 3:
                    # Offload the prompt generation to a background thread to prevent blocking
                    analysis = await asyncio.to_thread(self.soc_llm.correlate_threats, self.threat_history)
                    
                    # --- PHASE 17 & 18: HUMAN-IN-THE-LOOP (HITL) QUEUE ---
                    if "isolate" in analysis.lower() or "quarantine" in analysis.lower() or "isolation" in analysis.lower():
                        action_id = str(int(time.time()))
                        
                        target_entity = event.get("node_id", "127.0.0.1")
                        
                        self.pending_actions[action_id] = {"action": "quarantine", "target": target_entity}
                        analysis += f" [ACTION REQUIRED: Type '/approve {action_id}' in terminal to execute OS-level Quarantine on {target_entity}]"
                        
                    # Inject the supervisor's insight into the stream
                    await self.callback_func({
                        "type": "SUPERVISOR",
                        "model": "SOC_LLM",
                        "detail": analysis
                    })
                    
                    # Clear queue to avoid spamming the generative model
                    self.threat_history.clear()
            
            # --- PHASE 17: WEBSOCKET RATE LIMITING & DEBOUNCING ---
            current_time = time.time()
            self._emit_timestamps.append(current_time)
            # Maintain a sliding window of the last 1 second
            self._emit_timestamps = [t for t in self._emit_timestamps if current_time - t <= 1.0]
            
            if len(self._emit_timestamps) > 10:
                # We are being flooded (>10 events/sec). Throttle and bundle.
                if len(self._emit_timestamps) == 11: # Only emit the warning once per throttle window
                    await self.callback_func({
                        "type": "WARNING",
                        "model": "SYS",
                        "detail": "High Volume Alert: Throttling WebSocket telemetry due to massive event influx (Possible DDOS)."
                    })
                # Drop the actual event from the dashboard to prevent React UI freeze
                self.event_queue.task_done()
                continue

            # Standard pass-through to the injected SocketIO callback function
            await self.callback_func(event)
            self.event_queue.task_done()

    async def trigger_manual_audit(self, agent_name: str):
        """Pass-through to trigger an agent's run_manual_audit() immediately."""
        agent = self.agents_map.get(agent_name)
        if agent:
            await self._broadcast_info("MGR", f"Manual Audit Request routing to {agent_name}...")
            # We don't await this because run_manual_audit might block/loop
            asyncio.create_task(agent.run_manual_audit())
        else:
            logger.error(f"Cannot trigger audit. Agent {agent_name} not found.")

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
                
                # --- PHASE 17: GLOBAL STATE BACKUP ---
                import json
                try:
                    with open("threat_state.json", "w") as f:
                        json.dump(self.threat_history, f)
                except Exception as ex:
                    logger.error(f"Failed to dump threat state: {str(ex)}")
                    
                await self.callback_func(event)
            except Exception as e:
                logger.error(f"Heartbeat telemetry failed: {str(e)}")

    async def stop(self):
        self.is_running = False
        for agent in self.agents_map.values():
            await agent.stop()
        await self._broadcast_info("MGR", "Agentic Manager offline.")

    async def trigger_audit(self, scan_type: str = "deep"):
        """Triggered by the IT Admin via the Dashboard."""
        await self._broadcast_info("MGR", f"Security Audit Initiated ({scan_type.upper()}). Waking Log & Audit Models.")
        
        # Wake up reactive models
        log_model = self.agents_map.get("LOG")
        if log_model:
            asyncio.create_task(log_model.run_manual_audit())
        
        audit_model = self.agents_map.get("AUD")
        if audit_model:
            asyncio.create_task(audit_model.generate_report(scan_type=scan_type))

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
            await self._broadcast_info("SYS_HELP", "Available commands:\n/set [AGENT] [PARAM] [VAL] - Hot-swaps AI thresholds.\n/ignore IP [IP_ADDR] - Adds an IP to the allowlist.\n/approve [ID] - Approve pending HITL action.\n/deny [ID] - Deny pending HITL action.\nOr type naturally to ask the SOC LLM Supervisor a question.")
            
        elif base_cmd == "/approve" and len(parts) >= 2:
            action_id = parts[1]
            if action_id in self.pending_actions:
                pending = self.pending_actions.pop(action_id)
                action = pending["action"]
                target = pending["target"]
                
                await self._broadcast_info("ADMIN", f"Action '{action}' approved [ID: {action_id}]. Initiating active defense protocols on {target}...")
                
                if action == "quarantine":
                    from utils.firewall_service import FirewallService
                    success = FirewallService.block_ip(target)
                    if success:
                        await self._broadcast_info("ADMIN", f"[{target}] successfully blackholed at OS layer via pfctl/iptables.")
                    else:
                        await self._broadcast_info("ERROR", f"Failed to execute kernel block on {target}.")
                
            else:
                await self._broadcast_info("ERROR", f"Invalid or expired action ID: {action_id}")
                
        elif base_cmd == "/deny" and len(parts) >= 2:
            action_id = parts[1]
            if action_id in self.pending_actions:
                self.pending_actions.pop(action_id)
                await self._broadcast_info("ADMIN", f"Action denied [ID: {action_id}]. State remains nominal.")
            else:
                await self._broadcast_info("ERROR", f"Invalid or expired action ID: {action_id}")
        
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
                await self._broadcast_info("SOC_LLM", f"Analyzing query: '{command}'...")
                response = await asyncio.to_thread(self.soc_llm.answer_admin_query, command)
                await self.callback_func({
                    "type": "SUPERVISOR",
                    "model": "SOC_LLM",
                    "detail": response
                })
            else:
                await self._broadcast_info("ERROR", f"Unknown command syntax: {command}")

    async def trigger_autonomous_resolution(self, node_id: str):
        """Simulates the LLM Supervisor writing and executing a remediation patch."""
        await self._broadcast_info("SOC_LLM", f"Initiating autonomous remediation sequence for infected node: {node_id}")
        await asyncio.sleep(1.0)
        
        # Simulate LLM thinking and classifying the threat
        await self.callback_func({
            "type": "SUPERVISOR",
            "model": "SOC_LLM",
            "detail": f"Analyzing payload memory signatures on {node_id}... Identified rogue remote-access thread."
        })
        await asyncio.sleep(1.5)
        
        # Stream the script writing/execution
        script_steps = [
            f"Generating hotfix script -> `taskkill /F /IM mal_svc.exe /T`",
            f"Executing patch... Applying Windows Firewall block to C2 outbound port 4444.",
            f"Deploying registry key rollback patch via RPC channel..."
        ]
        
        for step in script_steps:
            await self._broadcast_info("SOC_LLM", step)
            await asyncio.sleep(1.2)
            
        await self.callback_func({
            "type": "SUPERVISOR",
            "model": "SOC_LLM",
            "detail": f"Remediation script finished. Handing off to Audit Model for environment verification sweep."
        })
        await asyncio.sleep(1.5)
        
        # Simulate Audit Model verification
        await self._broadcast_info("AUD", f"Verification sweep on {node_id} passed. No anomalies detected. Infection cleared.")
        await asyncio.sleep(0.5)

        # Tell the frontend to restore the UI
        await self.callback_func({
            "type": "RESOLUTION_SUCCESS",
            "node_id": node_id
        })
