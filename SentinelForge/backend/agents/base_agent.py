import asyncio
from typing import Dict, Any

class BaseAgent:
    """
    Abstract Base Class for the 5 Windows sub-models.
    Handles the common Event Queue for communicating with the Agentic Manager.
    """
    def __init__(self, name: str, event_queue: asyncio.Queue):
        self.name = name
        self.event_queue = event_queue
        self.is_active = False
        self.config = {}

    async def update_config(self, new_config: Dict[str, Any]):
        """Hot-swaps configuration parameters dynamically."""
        self.config.update(new_config)
        await self.emit_info(f"Loaded new dynamic configuration: {new_config}")

    async def start(self):
        """Main loop that starts monitoring."""
        self.is_active = True
        await self._monitor()

    async def stop(self):
        """Halts the monitoring loop."""
        self.is_active = False

    async def _monitor(self):
        """To be implemented by child classes."""
        raise NotImplementedError

    async def emit_alert(self, detail: str, severity: str = "error"):
        """Pushes an alert to the Manager's event queue."""
        event = {
            "type": "THREAT",
            "model": self.name,
            "detail": detail,
            "severity": severity
        }
        await self.event_queue.put(event)

    async def emit_info(self, detail: str):
        """Pushes an informational log to the Manager."""
        event = {
            "type": "INFO",
            "model": self.name,
            "detail": detail
        }
        await self.event_queue.put(event)
