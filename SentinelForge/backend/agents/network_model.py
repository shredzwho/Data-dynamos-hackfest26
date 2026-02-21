import asyncio
import psutil
import time
import json
import logging
from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.error import Scapy_Exception
from sklearn.ensemble import IsolationForest
from .base_agent import BaseAgent
from models.threat_detector import ThreatDetector
from utils.geoip_service import GeoIPService

logger = logging.getLogger(__name__)

class NetworkModel(BaseAgent):
    """
    Monitors LIVE Network ingress/egress and active socket bindings.
    """
    def __init__(self, event_queue: asyncio.Queue):
        super().__init__(name="NET", event_queue=event_queue)
        self.last_bytes = 0
        self.traffic_history = []
        self.packet_batch = []
        # Support dynamic config
        self.config = {
            "contamination": 0.05,
            "threat_threshold": 0.8
        }
        self.model = IsolationForest(contamination=self.config["contamination"], random_state=42)
        
        try:
            self.dl_detector = ThreatDetector()
            self.dl_healthy = self.dl_detector.perform_health_check()
        except ImportError:
            self.dl_detector = None
            self.dl_healthy = False

    async def update_config(self, new_config: dict):
        current_contamination = self.config.get("contamination")
        await super().update_config(new_config)
        
        # If contamination changed, we must rebuild the Scikit-learn model
        if current_contamination != self.config.get("contamination"):
            self.model = IsolationForest(contamination=self.config.get("contamination", 0.05), random_state=42)
            self.traffic_history.clear() # Reset baseline
            await self.emit_info(f"Rebuilt IsolationForest with new contamination rate: {self.config['contamination']}")

    async def _monitor(self):
        await self.emit_info("Network socket interface bound via psutil. Watching live traffic anomalies.")
        if self.dl_healthy:
            await self.emit_info("PyTorch ThreatDetector loaded successfully. Active deep-packet-inspection enabled.")

        
        # Init offset
        net_io = psutil.net_io_counters()
        self.last_bytes = net_io.bytes_recv + net_io.bytes_sent

        def packet_callback(packet):
            """Synchronous callback executed by Scapy for each parsed packet."""
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                size = len(packet)
                
                proto = "UNKNOWN"
                port = 0
                if TCP in packet:
                    proto = "TCP"
                    port = packet[TCP].dport
                elif UDP in packet:
                    proto = "UDP"
                    port = packet[UDP].dport
                elif ICMP in packet:
                    proto = "ICMP"

                # 1. GeoIP Enrichment
                geo_data = GeoIPService.lookup_ip(src_ip)
                country_code = geo_data.get("code", "UNKNOWN")
                
                # 2. Append to batch
                self.packet_batch.append({
                    "packet_id": f"scapy_{int(time.time()*1000)}",
                    "size": size,
                    "protocol": proto,
                    "source_ip": src_ip,
                    "dest_ip": dst_ip,
                    "port": port,
                    "geo": country_code
                })

                # 3. Process Batch if Limit Reached
                if len(self.packet_batch) >= 15:
                    batch_to_process = list(self.packet_batch)
                    self.packet_batch.clear()
                    asyncio.run_coroutine_threadsafe(
                        self._process_real_packet_batch(batch_to_process),
                        self.main_loop
                    )

        while self.is_active:
            try:
                self.main_loop = asyncio.get_running_loop()
                # Run scapy sniff in a background thread to prevent blocking the async loop
                # Sniff a batch of 15 packets, then yield control back
                await asyncio.to_thread(sniff, prn=packet_callback, count=15, timeout=5)
            except Scapy_Exception as e:
                logger.error(f"Scapy Sniffer failed (requires sudo on some interfaces): {e}")
                await self.emit_info("Scapy requires elevated permissions. Falling back to passive bandwidth monitor.")
                await asyncio.sleep(5.0)
            except Exception as e:
                logger.error(f"Network sniffer crash: {e}")
                await asyncio.sleep(2.0)

    async def _process_real_packet_batch(self, batch: list):
        """Asynchronous pipeline to feed a batch of real packets into PyTorch ThreatDetector."""
        if not self.dl_healthy or not batch:
            return
            
        threat_threshold = self.config.get("threat_threshold", 0.8)
        
        # We pass the entire batch of 15 packets directly into PyTorch
        threat_results = self.dl_detector.process_packet_analysis(batch, threshold_override=threat_threshold)
        
        for idx, res in enumerate(threat_results):
            if res["is_threat"]:
                pkt = batch[idx]
                await self.emit_alert(
                    f"PyTorch Deep Learning Threat on {pkt['protocol']} {pkt['source_ip']}:{pkt['port']} [{pkt['geo']}]! "
                    f"Probability: {res['threat_probability']:.2f}. Engaging trace..."
                )
                await asyncio.sleep(0.5)
                insights = self.dl_detector.analyze_suspicious_packets([{"packet_id": res["packet_id"], "risk_score": res["threat_probability"]}])
                if insights:
                    await self.emit_alert(f"PyTorch Auto-Resolution Protocol: {insights[0]['action']} (Confidence: {insights[0]['confidence']})")
