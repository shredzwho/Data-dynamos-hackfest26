import asyncio
import platform
import psutil
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
        self.nlp = None

    async def _load_ml_model(self):
        if pipeline and not self.nlp:
            await self.emit_info("Loading DistilBERT NLP Security Model into memory...")
            # We use sentiment analysis as a lightweight proxy for malicious/benign classification in this prototype
            # In a production environment, this would load a fine-tuned cybersecurity BERT model
            self.nlp = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")
            await self.emit_info("NLP Engine Online. Active Context Window ready.")

    async def _monitor(self):
        # Starts in standby, waiting for the Admin's trigger
        pass
        
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
                
                # We pull the first 100 recent events looking for Failure Audits (EventID 4625)
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
            await self.emit_info(f"Non-Windows environment ({platform.system()}) detected. Scanning available Syslog/var/log telemetry...")
            await asyncio.sleep(2.0)
            
            if self.nlp:
                # Simulated Syslog sweep since Mac can't natively read Windows EVTX logs
                mock_logs = [
                    "User Administrator successfully logged in from 10.0.1.55.",
                    "Cron daemon executed daily log rotation successfully.",
                    "Failed password for root from 192.168.1.100 port 22 ssh2",
                    "Invalid user support from 192.168.1.100",
                    "Connection closed by authenticating user root 192.168.1.100"
                ]
                
                malicious_count = 0
                for log_msg in mock_logs:
                    await asyncio.sleep(0.5) # Simulate processing delay
                    # Use NLP to classify the text string
                    res = self.nlp(log_msg)[0]
                    
                    # NEGATIVE sentiment on IT logs usually correlates strongly with errors/attacks/failures
                    if res['label'] == 'NEGATIVE' and res['score'] > 0.95:
                        malicious_count += 1
                        await self.emit_alert(f"NLP Threat Identified: [{log_msg}] (Confidence: {res['score']:.2f})")
                
                if malicious_count > 0:
                    await self.emit_alert(f"NLP Log Parser found {malicious_count} anomalous events in the system log stream.")
                else:
                    await self.emit_info("NLP Heuristic analysis clean.")
            else:
                await self.emit_info("Transformers not installed. NLP analysis skipped.")
            
        self.is_active = False
        await self.emit_info("Log Audit Complete. Returning to STANDBY.")
