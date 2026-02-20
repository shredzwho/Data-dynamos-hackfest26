import asyncio
import psutil
import numpy as np
from sklearn.ensemble import IsolationForest
from .base_agent import BaseAgent

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

    async def _monitor(self):
        await self.emit_info("Network socket interface bound via psutil. Watching live traffic anomalies.")
        
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

            except Exception as e:
                pass
