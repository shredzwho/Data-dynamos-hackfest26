import asyncio
import psutil
import urllib.request
import logging
import os
import ssl
from .base_agent import BaseAgent

logger = logging.getLogger(__name__)

class WebModel(BaseAgent):
    """
    Monitors LIVE open ports, outbound C2 connections (Tor), and Infostealer database access.
    """
    def __init__(self, event_queue: asyncio.Queue):
        super().__init__(name="WEB", event_queue=event_queue)
        self.tor_nodes = set()
        self.whitelisted_ports = {80, 443, 3000, 5000, 5001, 5432, 8000, 8080, 6379, 27017, 8023, 3389}
        self.trusted_browsers = {"Google Chrome", "chrome", "Brave Browser", "brave", "Firefox", "firefox", "Safari", "safari", "msedge"}

    async def start(self):
        await self._fetch_tor_nodes()
        await super().start()

    async def _fetch_tor_nodes(self):
        try:
            await self.emit_info("Fetching latest Tor Exit Node directory...")
            def fetch():
                req = urllib.request.Request(
                    "https://check.torproject.org/torbulkexitlist",
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"}
                )
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                    return response.read().decode('utf-8').splitlines()
            nodes = await asyncio.to_thread(fetch)
            self.tor_nodes = set(n.strip() for n in nodes if n.strip() and not n.startswith("#"))
            await self.emit_info(f"Loaded {len(self.tor_nodes)} Tor Exit Nodes into memory.")
        except Exception as e:
            logger.error(f"Failed to fetch Tor nodes: {e}")
            await self.emit_info("Could not fetch Tor node list. C2 Dark Web monitoring degraded.")

    def _run_infostealer_scan(self):
        alerts = []
        infostealer_targets = ["Login Data", "Cookies", "Web Data", "key3.db", "key4.db", "logins.json"]
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info.get('name', '')
                if not name or any(tb.lower() in name.lower() for tb in self.trusted_browsers):
                    continue
                
                for f in proc.open_files():
                    if any(target in f.path for target in infostealer_targets):
                        alerts.append(f"INFOSTEALER DETECTED: Process '{name}' (PID {proc.info['pid']}) is reading sensitive browser db: {f.path}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue
        return alerts

    async def _monitor(self):
        await self.emit_info("Web defense active: Monitoring Tor C2, Rogue Bind Shells, and Infostealers.")
        while self.is_active:
            await asyncio.sleep(8.0)
            
            # 1. Monitor Infostealers (File Descriptors)
            infostealer_alerts = await asyncio.to_thread(self._run_infostealer_scan)
            for alert in infostealer_alerts:
                await self.emit_alert(alert)

            # 2. Network Connections (Rogue Listeners & Tor C2)
            try:
                # Use psutil.net_connections instead of iteration to be faster, handle AccessDenied gracefully
                connections = psutil.net_connections(kind='inet')
                rogue_listens = []
                tor_conns = []
                
                for c in connections:
                    # Rogue Listener
                    if c.status == 'LISTEN' and c.laddr:
                        port = c.laddr.port
                        if port not in self.whitelisted_ports:
                            try:
                                proc_name = psutil.Process(c.pid).name() if c.pid else "Unknown"
                            except:
                                proc_name = "Unknown"
                            rogue_listens.append((port, proc_name))
                            
                    # Tor C2
                    elif c.status == 'ESTABLISHED' and c.raddr:
                        if c.raddr.ip in self.tor_nodes:
                            try:
                                proc_name = psutil.Process(c.pid).name() if c.pid else "Unknown"
                            except:
                                proc_name = "Unknown"
                            tor_conns.append((c.raddr.ip, proc_name))

                for port, proc in set(rogue_listens):
                    await self.emit_alert(f"ROGUE LISTENER DETECTED: Unauthorized bind shell on port {port} by process '{proc}'!")
                    
                for ip, proc in set(tor_conns):
                    await self.emit_alert(f"DARK WEB C2 DETECTED: '{proc}' established outbound connection to Tor Node {ip}!")
                    
            except psutil.AccessDenied:
                # Graceful degradation on macOS when non-root
                pass
            except Exception as e:
                pass
