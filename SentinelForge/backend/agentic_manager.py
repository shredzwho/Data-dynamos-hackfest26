import asyncio
import logging
import psutil
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
        
        # Instantiate 5 specialized AI Agents
        self.network_model = NetworkModel(self.event_queue)
        self.memory_model = MemoryModel(self.event_queue)
        self.web_model = WebModel(self.event_queue)
        self.log_model = LogModel(self.event_queue)
        self.audit_model = AuditModel(self.event_queue)

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
