import asyncio
import psutil
import platform
import hashlib
import os
import json
from .base_agent import BaseAgent

class AuditModel(BaseAgent):
    """
    Phase 16 Deep Compliance Engine. 
    Performs Tri-Modal (Deep/Stealth/Smart) Vulnerability Audits and FIM scanning.
    """
    def __init__(self, event_queue: asyncio.Queue, agentic_manager_ref=None):
        super().__init__(name="AUDIT", event_queue=event_queue)
        self.agentic_manager = agentic_manager_ref
        
        # Simulated Vulnerable Ports List (Legacy/Unencrypted)
        self.dangerous_ports = {
            21: "FTP (Unencrypted)",
            23: "Telnet (Unencrypted)",
            3389: "RDP (Exposed Remote Access)",
            445: "SMB (WannaCry Vector)"
        }
        
    async def _monitor(self):
        # Driven purely by the Agentic Manager command
        while self.is_active:
            await asyncio.sleep(60.0)
        
    def _scan_open_ports(self):
        """Checks for dangerous listening ports."""
        vulnerable = []
        try:
            conns = psutil.net_connections(kind='inet')
            for c in conns:
                if c.status == 'LISTEN' and c.laddr.port in self.dangerous_ports:
                    vulnerable.append({
                        "port": c.laddr.port,
                        "risk": self.dangerous_ports[c.laddr.port]
                    })
        except psutil.AccessDenied:
            pass # Requires root on some OS
        return vulnerable

    def _simulated_fim_scan(self):
        """Simulates checking core OS binaries for Rootkit tampering."""
        # For demonstration, we check our own Pythons files, but flag a mock failure randomly
        critical_files_passed = [
            "/Windows/System32/ntoskrnl.exe",
            "/Windows/System32/hal.dll"
        ]
        tampered_files = []
        
        # Simulate a 10% chance of finding a FIM anomaly during a Deep Scan
        import random
        if random.random() < 0.10:
            tampered_files.append({
                "file": "/Windows/System32/svchost.exe",
                "issue": "SHA-256 Hash Mismatch (Possible Process Hollowing Target altered on disk)"
            })
            
        return {
            "passed": len(critical_files_passed),
            "tampered": tampered_files
        }

    async def generate_report(self, scan_type: str = "deep"):
        """Executes the Compliance Sweep based on chosen mode."""
        host = platform.node()
        await self.emit_info(f"Initiating [{scan_type.upper()}] Systems Audit on {host}")
        
        report = {
            "host": host,
            "scan_mode": scan_type,
            "vulnerabilities": [],
            "system_health": {},
            "ai_health": {}
        }
        score = 100
        
        try:
            # 1. Base Hardware Health
            cpu_load = psutil.cpu_percent(interval=1.0)
            ram_load = psutil.virtual_memory().percent
            report["system_health"] = {"cpu": cpu_load, "ram": ram_load}
            
            if cpu_load > 85: score -= 5
            if ram_load > 90: score -= 5
            
            # 2. AI Model Health Check
            if self.agentic_manager:
                 net_active = self.agentic_manager.agents_map.get("NET", None) is not None
                 mem_active = self.agentic_manager.agents_map.get("MEM", None) is not None
                 
                 report["ai_health"] = {
                     "network_pytorch_engine": "ONLINE" if net_active else "OFFLINE",
                     "memory_hymem_engine": "ONLINE" if mem_active else "OFFLINE"
                 }
                 
                 if not net_active:
                     score -= 30
                     report["vulnerabilities"].append({"type": "ML_OFFLINE", "desc": "PyTorch Network Thread is down."})
                 if not mem_active:
                     score -= 30
                     report["vulnerabilities"].append({"type": "ML_OFFLINE", "desc": "HyMem Memory Thread is down."})

            # 3. Deep / Smart Mode Checks (Heavier lifting)
            if scan_type in ["deep", "smart"]:
                await asyncio.sleep(1.5) # Simulate IO load
                
                # Active Port Scan
                exposed_ports = self._scan_open_ports()
                if exposed_ports:
                     for ep in exposed_ports:
                          score -= 15
                          report["vulnerabilities"].append({
                              "type": "PORT_EXPOSED",
                              "desc": f"Port {ep['port']} open: {ep['risk']}"
                          })
                
                # FIM Sweep
                fim_results = self._simulated_fim_scan()
                if fim_results["tampered"]:
                    for tf in fim_results["tampered"]:
                         score -= 25
                         report["vulnerabilities"].append({
                             "type": "FIM_FAILURE",
                             "desc": f"{tf['file']} - {tf['issue']}"
                         })
                         
            # 4. Stealth Mode
            if scan_type == "stealth":
                await self.emit_info("Stealth Scan bypassing active probes to prevent EDR detection.")
                # We artificially hide port logs to maintain zero footprint

            report["compliance_score"] = max(0, score)
            
            # Pipe structured JSON report via AUDIT_RESULT
            event = {
                "type": "AUDIT_RESULT",
                "model": "AUDIT",
                "score": report["compliance_score"],
                "report_json": json.dumps(report)
            }
            await self.event_queue.put(event)
            
        except Exception as e:
            await self.emit_alert(f"Failed to generate Deep Audit Report: {str(e)}")
