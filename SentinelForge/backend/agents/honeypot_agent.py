import asyncio
import logging
from typing import Dict, Any
from .base_agent import BaseAgent

logger = logging.getLogger(__name__)

class HoneypotAgent(BaseAgent):
    """
    Active Defense (IPS) Module: Spawns fake TCP listeners on highly targeted ports.
    Instantly flags connecting IPs as malicious port scanners.
    """
    def __init__(self, event_queue: asyncio.Queue, agentic_manager_ref=None):
        super().__init__(name="HONEYPOT", event_queue=event_queue)
        self.agentic_manager_ref = agentic_manager_ref
        
        # We use 8023 (Alt Telnet) and 3389 (RDP) to avoid requiring root for port < 1024
        self.trap_ports = [8023, 3389]
        self.servers = []

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Callback when an attacker connects to the honeypot."""
        addr = writer.get_extra_info('peername')
        attacker_ip = addr[0] if addr else "Unknown"
        
        port = writer.get_extra_info('sockname')[1]
        
        # Immediately flag this as a critical zero-day intrusion attempt
        await self.emit_alert(f"HONEYPOT TRIPPED! Unsolicited scan detected from {attacker_ip} targeting restricted port {port}.")
        
        # Fire the Pub/Sub network drop signal
        if self.agentic_manager_ref:
            from utils.firewall_service import FirewallService
            blocked = FirewallService.block_ip(attacker_ip)
            if blocked:
                await self.emit_alert(f"ACTIVE DEFENSE: {attacker_ip} automatically blackholed at OS layer via pfctl/iptables.")

        # Optionally mimic a fake banner to keep them on the line temporarily
        try:
            writer.write(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n")
            await writer.drain()
            await asyncio.sleep(2.0)
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except ConnectionResetError:
                pass

    async def start(self):
        """Overrides base start to initialize TCP servers instead of a loop."""
        print(f"DEBUG: HoneypotAgent.start() called on {self.trap_ports}")
        self.is_active = True
        
        for port in self.trap_ports:
            try:
                server = await asyncio.start_server(self._handle_connection, '0.0.0.0', port)
                self.servers.append(server)
                print(f"DEBUG: Honeypot listening tightly on port {port}")
                logger.info(f"Honeypot active. Listening for scanners on port {port}")
            except Exception as e:
                logger.error(f"Failed to bind Honeypot to port {port}: {e}")
                
        await self.emit_info(f"Deception modules engaged on {len(self.servers)} ports.")
        
        # Keep the agent alive
        while self.is_active:
            await asyncio.sleep(3600)

    async def stop(self):
        self.is_active = False
        for server in self.servers:
            server.close()
            await server.wait_closed()
        await self.emit_info("Honeypot listeners decommissioned.")
