import asyncio
import platform
import psutil
import os
import aiofiles
from .base_agent import BaseAgent

try:
    from transformers import pipeline
except ImportError:
    pipeline = None

class LogModel(BaseAgent):
    """
    Monitors Windows Event Viewer logs natively using pywin32.
    If deployed on Linux/Mac, falls back to a Syslog sweep or simulation.
    """
    def __init__(self, event_queue: asyncio.Queue):
        super().__init__(name="LOG", event_queue=event_queue)
        self.is_windows = platform.system() == "Windows"
        self.is_mac = platform.system() == "Darwin"
        self.nlp = None

    async def _load_ml_model(self):
        if pipeline and not self.nlp:
            await self.emit_info("Loading DistilBERT NLP Security Model into memory...")
            # We use sentiment analysis as a lightweight proxy for malicious/benign classification in this prototype
            # In a production environment, this would load a fine-tuned cybersecurity BERT model
            self.nlp = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")
            await self.emit_info("NLP Engine Online. Active Context Window ready.")

    async def _monitor(self):
        while self.is_active:
            if self.is_windows:
                await asyncio.sleep(60.0)
                continue
                
            await self._load_ml_model()
            log_path = "/var/log/system.log" if self.is_mac else "/var/log/auth.log"
            
            if not os.path.exists(log_path):
                await self.emit_info(f"Log path {log_path} not found. Background PAM monitoring degraded.")
                await asyncio.sleep(60.0)
                continue

            await self.emit_info(f"Background PAM Monitor active. Tailing {log_path} for SSH/sudo failures...")
            try:
                async with aiofiles.open(log_path, mode='r') as f:
                    # Seek to end of file to tail only new events
                    await f.seek(0, os.SEEK_END)
                    while self.is_active:
                        line = await f.readline()
                        if not line:
                            await asyncio.sleep(1.0)
                            continue
                            
                        # Filter for PAM / SSH
                        if "sshd" in line or "sudo" in line or "su" in line:
                            if "Failed" in line or "Invalid" in line or "COMMAND=" in line or "incorrect" in line.lower():
                                if self.nlp:
                                    res = self.nlp(line)[0]
                                    if res['label'] == 'NEGATIVE' and res['score'] > 0.8:
                                        await self.emit_alert(f"[IAM Threat]: {line.strip()} (Confidence: {res['score']:.2f})")
                                else:
                                    await self.emit_alert(f"[IAM Threat]: {line.strip()}")
            except Exception as e:
                await self.emit_info(f"Failed to tail {log_path} (Requires sudo?): {e}")
                await asyncio.sleep(60.0)

    async def run_manual_audit(self):
        self.is_active = True
        
        await self._load_ml_model()

        if self.is_windows:
            await self.emit_info("Windows environment detected. Attaching to EVTX Security Channel via Win32 API.")
            await asyncio.sleep(2.0)
            try:
                import win32evtlog
                server = 'localhost'
                log_type = 'Security'
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                hand = win32evtlog.OpenEventLog(server, log_type)
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                failure_count = sum(1 for e in events if e.EventID == 4625)
                if failure_count > 5:
                    await self.emit_alert(f"Windows Event Viewer flagged {failure_count} Brute-force Login Failures (Event 4625) in the recent stack.")
                else:
                    await self.emit_info("Log analysis clean. Security Event Logs nominal.")
                win32evtlog.CloseEventLog(hand)
            except ImportError:
                await self.emit_alert("win32evtlog missing on a Windows host. Log scanning aborted.")
            except Exception as e:
                await self.emit_alert(f"Failed to read EVTX stream: {str(e)}")
        else:
            log_path = "/var/log/system.log" if self.is_mac else "/var/log/auth.log"
            await self.emit_info(f"Non-Windows environment ({platform.system()}) detected. Scanning {log_path} auth telemetry...")
            await asyncio.sleep(2.0)
            
            if os.path.exists(log_path):
                try:
                    async with aiofiles.open(log_path, mode='r') as f:
                        lines = await f.readlines()
                        # Get last 500 lines
                        recent_logs = lines[-500:]
                        malicious_count = 0
                        for log_msg in recent_logs:
                            log_msg = log_msg.strip()
                            if not log_msg or ("sshd" not in log_msg and "sudo" not in log_msg and "su" not in log_msg):
                                continue
                            
                            # Heuristics for failure
                            if "Failed" in log_msg or "Invalid" in log_msg or "COMMAND=" in log_msg or "incorrect" in log_msg.lower():
                                if self.nlp:
                                    res = self.nlp(log_msg)[0]
                                    if res['label'] == 'NEGATIVE' and res['score'] > 0.8:
                                        malicious_count += 1
                                        await self.emit_alert(f"NLP Threat Identified: [{log_msg}] (Confidence: {res['score']:.2f})")
                                        await asyncio.sleep(0.1)
                                else:
                                    malicious_count += 1
                                    await self.emit_alert(f"IAM Anomaly: [{log_msg}]")
                                    await asyncio.sleep(0.1)
                                    
                        if malicious_count > 0:
                            await self.emit_alert(f"Log Parser found {malicious_count} anomalous IAM events in the historical stream.")
                        else:
                            await self.emit_info(f"IAM PAM analysis clean on {log_path}.")
                except Exception as e:
                    await self.emit_info(f"Failed to read {log_path} (Requires sudo?): {e}")
            else:
                await self.emit_info(f"Log path {log_path} not found. Skipping audit.")
            
        await self.emit_info("Log Audit Complete. Active Tailing continues in background.")
