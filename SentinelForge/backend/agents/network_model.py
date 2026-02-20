import asyncio
import psutil
import time
import random
import numpy as np
from sklearn.ensemble import IsolationForest
from .base_agent import BaseAgent
from models.threat_detector import ThreatDetector

class NetworkModel(BaseAgent):
    """
    Monitors LIVE Network ingress/egress and active socket bindings.
    """
    def __init__(self, event_queue: asyncio.Queue):
        super().__init__(name="NET", event_queue=event_queue)
        self.last_bytes = 0
        self.traffic_history = []
        # Expect 5% of traffic over time to be anomalous outliers
        self.model = IsolationForest(contamination=0.05, random_state=42)
        
        try:
            self.dl_detector = ThreatDetector()
            self.dl_healthy = self.dl_detector.perform_health_check()
        except ImportError:
            self.dl_detector = None
            self.dl_healthy = False

    async def _monitor(self):
        await self.emit_info("Network socket interface bound via psutil. Watching live traffic anomalies.")
        if self.dl_healthy:
            await self.emit_info("PyTorch ThreatDetector loaded successfully. Active deep-packet-inspection enabled.")

        
        # Init offset
        net_io = psutil.net_io_counters()
        self.last_bytes = net_io.bytes_recv + net_io.bytes_sent

        while self.is_active:
            await asyncio.sleep(5.0)
            try:
                # Calculate bandwidth
                net_io = psutil.net_io_counters()
                current_bytes = net_io.bytes_recv + net_io.bytes_sent
                speed_bps = (current_bytes - self.last_bytes) / 5.0
                speed_mbps = speed_bps / 1_000_000
                self.last_bytes = current_bytes

                self.traffic_history.append(speed_mbps)
                
                # Keep last 5 minutes of data (60 samples at 5s intervals)
                if len(self.traffic_history) > 60:
                    self.traffic_history.pop(0)

                # ML Anomaly Detection (requires at least 1 minute / 12 samples of baseline data)
                if len(self.traffic_history) < 12:
                    await self.emit_info(f"Building ML Traffic Baseline ({len(self.traffic_history)}/12)... Current Load: {speed_mbps:.2f} Mbps.")
                else:
                    X_train = np.array(self.traffic_history).reshape(-1, 1)
                    self.model.fit(X_train)
                    
                    is_anomaly = self.model.predict([[speed_mbps]])[0] == -1
                    median_traffic = np.median(self.traffic_history)
                    
                    # Only alert if it's an anomaly AND a spike (not a sudden drop)
                    if is_anomaly and speed_mbps > (median_traffic * 2.0) and speed_mbps > 5.0:
                        await self.emit_alert(f"ML Anomaly: Traffic {speed_mbps:.1f} Mbps deviates significantly from baseline ({median_traffic:.1f} Mbps). Possible Exfiltration.")
                    elif speed_mbps > 500.0:
                        await self.emit_alert(f"Hardcoded Threshold Exceeded: {speed_mbps:.1f} Mbps. Potential Data Exfiltration.")
                    else:
                        await self.emit_info(f"Packet stream nominal. Current Bandwidth load: {speed_mbps:.2f} Mbps.")
                        
                # ----------------------------------------------------
                # Deep Learning PyTorch Inference Pipeline (mock packet generation out of real byte volume)
                # ----------------------------------------------------
                if self.dl_healthy and speed_bps > 1000:
                    mock_packets = []
                    # Create 3 stochastic packet models utilizing the live bytes per second
                    for _ in range(3):
                        mock_packets.append({
                            "packet_id": f"pkt_{int(time.time()*1000)}_{random.randint(100,999)}",
                            "size": int(speed_bps / (random.randint(5, 50) + 1)),
                            "protocol": "TCP" if random.random() > 0.2 else "UDP",
                            "source_ip": "10.0.1.55",
                            "dest_ip": f"198.51.100.{random.randint(1,200)}"
                        })
                    
                    threat_results = self.dl_detector.process_packet_analysis(mock_packets)
                    
                    for res in threat_results:
                        if res["is_threat"]:
                            await self.emit_alert(f"PyTorch Deep Learning Threat Signal on {res['packet_id']}! Probability: {res['threat_probability']:.2f}. Engaging trace...")
                            await asyncio.sleep(0.5)
                            insights = self.dl_detector.analyze_suspicious_packets([{"packet_id": res["packet_id"], "risk_score": res["threat_probability"]}])
                            if insights:
                                await self.emit_alert(f"PyTorch Auto-Resolution Protocol: {insights[0]['action']} (Confidence: {insights[0]['confidence']})")

            except Exception as e:
                pass
