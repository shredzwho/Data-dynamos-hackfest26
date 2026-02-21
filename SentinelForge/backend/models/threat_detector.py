import torch
import torch.nn as nn
import numpy as np
from pydantic import BaseModel
from typing import List, Dict, Any

class PacketAnalysis(BaseModel):
    packet_id: str
    source_ip: str
    dest_ip: str
    protocol: str
    size: int

class SuspiciousPacket(BaseModel):
    packet_id: str
    reason: str
    risk_score: float

class ThreatDetectorModel(nn.Module):
    def __init__(self, input_size: int = 5, hidden_size: int = 16):
        super(ThreatDetectorModel, self).__init__()
        # Simplified PyTorch template for threat anomaly detection
        self.fc1 = nn.Linear(input_size, hidden_size)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(hidden_size, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        out = self.fc1(x)
        out = self.relu(out)
        out = self.fc2(out)
        out = self.sigmoid(out)
        return out

class ThreatDetector:
    def __init__(self):
        """
        Initializes the Threat Detector with a mock PyTorch model.
        In a real scenario, weights would be pre-loaded here.
        """
        self.model = ThreatDetectorModel()
        self.model.eval() # Set to evaluation mode
        self.is_healthy = True

    def perform_health_check(self) -> bool:
        """
        Health check to assure model weights are loaded and model is responsive.
        """
        try:
            # Send dummy tensor to test capability
            dummy_input = torch.rand(1, 5)
            with torch.no_grad():
                _ = self.model(dummy_input)
            self.is_healthy = True
            return True
        except Exception as e:
            print(f"Health Check Failed for ThreatDetector: {e}")
            self.is_healthy = False
            return False

    def process_packet_analysis(self, packets: List[Dict[str, Any]], threshold_override: float = 0.8) -> List[Dict[str, Any]]:
        """
        Analyze a list of network packets using PyTorch Feed-Forward Deep Learning.
        """
        from utils.geoip_service import GeoIPService
        
        results = []
        for packet in packets:
            # 1. Normalized Size (MTU 1500 limit)
            size_norm = min(packet.get("size", 0) / 1500.0, 1.0)
            
            # 2. Protocol Encoding
            proto_val = 0.0
            proto = packet.get("protocol")
            if proto == "TCP": proto_val = 1.0
            elif proto == "UDP": proto_val = 0.5
            elif proto == "ICMP": proto_val = 0.2
            
            # 3. Port Risk Factor
            port = packet.get("port", 0)
            high_risk_ports = [21, 22, 23, 139, 445, 3389, 8023]
            port_risk = 1.0 if port in high_risk_ports else 0.1
            
            # 4. Geo Risk Factor
            country_code = packet.get("geo", "UNKNOWN")
            geo_risk = GeoIPService.get_geo_risk_factor(country_code)
            
            # 5. Generic Jitter / Timing Anomaly (Simulated baseline for MVP)
            timing_risk = 0.2
            
            # Assemble the tensor array (5 Features)
            features = np.array([
                size_norm, 
                proto_val, 
                port_risk, 
                geo_risk, 
                timing_risk
            ], dtype=np.float32)
            
            tensor_input = torch.tensor(features).unsqueeze(0)
            
            with torch.no_grad():
                threat_prob = self.model(tensor_input).item()

            results.append({
                "packet_id": packet.get("packet_id"),
                "threat_probability": threat_prob,
                "is_threat": threat_prob > threshold_override
            })
            
        return results

    def analyze_suspicious_packets(self, suspicious_candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deep dive into already-flagged suspicious packets.
        """
        insights = []
        for candidate in suspicious_candidates:
            # High severity simulation
            risk = candidate.get("risk_score", 0.0)
            if risk > 0.9:
                insights.append({
                    "packet_id": candidate.get("packet_id"),
                    "action": "BLOCK_IP",
                    "confidence": 0.95
                })
            else:
                insights.append({
                    "packet_id": candidate.get("packet_id"),
                    "action": "MONITOR",
                    "confidence": 0.60
                })
        return insights
