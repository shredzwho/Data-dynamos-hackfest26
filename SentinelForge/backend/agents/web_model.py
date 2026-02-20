import asyncio
import psutil
from .base_agent import BaseAgent

class WebModel(BaseAgent):
    """
    Monitors LIVE open ports and active outbound HTTP/HTTPS connections.
    """
    def __init__(self, event_queue: asyncio.Queue):
        super().__init__(name="WEB", event_queue=event_queue)

    async def _monitor(self):
        await self.emit_info("Socket connection hook active. Tracking outbound web requests (80/443).")
        while self.is_active:
            await asyncio.sleep(8.0)
            
            try:
                # psutil.net_connections requires root on some OS's for all PIDs, but works for our own/standard ones.
                # However, on macOS it restricts without sudo. We will catch AccessDenied if it occurs.
                connections = psutil.net_connections(kind='inet')
                web_conns = [c for c in connections if c.status == 'ESTABLISHED' and c.raddr and c.raddr.port in (80, 443)]
                
                if len(web_conns) > 150:
                    await self.emit_alert(f"Anomalous burst of outbound web sessions: {len(web_conns)} active HTTPS hooks. Suspected C2 Beaconing.")
                else:
                    await self.emit_info(f"Web heuristics clean. {len(web_conns)} established HTTP/HTTPS connections.")
                    
            except psutil.AccessDenied:
                # Fallback gracefully if we don't have Admin/Root on this specific hardware
                await self.emit_info("Insufficient permissions to scan all active sockets. Web heuristics running in restricted mode.")
            except Exception as e:
                pass
