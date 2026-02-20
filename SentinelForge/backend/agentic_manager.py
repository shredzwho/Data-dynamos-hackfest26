import asyncio
import logging
import json
import redis.asyncio as redis
from typing import Dict, Any, List

from models import ThreatDetector, LogAnomalyModel

logger = logging.getLogger(__name__)

class AgenticManager:
    """
    Central orchestrator routing data to specialized AI models
    and monitoring their health concurrently.
    """
    def __init__(self):
        # Initialize specialist models
        self.network_model = ThreatDetector()
        self.log_model = LogAnomalyModel()
        
        # Placeholders
        self.memory_model = None
        self.web_model = None
        self.audit_model = None

        # Setup Async Redis Client (Broker for frontend WS)
        self.redis = redis.from_url("redis://localhost:6379/0", decode_responses=True)

    async def _check_network(self):
        return await asyncio.to_thread(self.network_model.perform_health_check)
        
    async def _check_log(self):
        return await asyncio.to_thread(self.log_model.perform_health_check)

    async def run_health_checks(self):
        """
        Concurrently perform health checks on all loaded specialist models 
        using Python 3.11+ TaskGroup for maximum speed.
        """
        logger.info("Starting concurrent health checks for specialist models...")
        statuses = {}
        
        async with asyncio.TaskGroup() as tg:
            net_task = tg.create_task(self._check_network())
            log_task = tg.create_task(self._check_log())

        statuses = {
            "network_model": "Healthy" if net_task.result() else "Degraded",
            "log_model": "Healthy" if log_task.result() else "Degraded",
            "memory_model": "Offline",
            "web_model": "Offline",
            "audit_model": "Offline"
        }
        
        return statuses

    async def ingest_network_packets(self, packets: List[Dict[str, Any]]):
        """
        Route network packets to the network model and publish 
        threats synchronously to Redis Streams.
        """
        if not self.network_model.is_healthy:
            return []
            
        # Heavy CPU work offloaded to thread
        results = await asyncio.to_thread(self.network_model.process_packet_analysis, packets)
        
        # Publish threats to Redis channel "dashboard_events"
        for res in results:
            if res.get("is_threat"):
                event = {
                    "event": "new_threat_alert",
                    "data": {
                        "id": res.get("packet_id"),
                        "type": "Network Anomaly",
                        "severity": "High",
                        "probability": res.get("threat_probability")
                    }
                }
                await self.redis.publish("dashboard_events", json.dumps(event))
                
        return results
        
    async def ingest_system_logs(self, logs: List[str]):
        """
        Route log strings to Transformer log anomaly model.
        """
        if not self.log_model.is_healthy:
            return []
            
        results = []
        for log in logs:
            res = await asyncio.to_thread(self.log_model.analyze_log, log)
            results.append(res)
            
            if res.get("is_anomaly"):
                event = {
                    "event": "new_threat_alert",
                    "data": {
                        "id": f"log_{hash(log)}",
                        "type": "Log Anomaly Detection",
                        "severity": "Critical",
                        "probability": res.get("risk_score")
                    }
                }
                await self.redis.publish("dashboard_events", json.dumps(event))
        return results

    async def ingest_suspicious_packets(self, packets: List[Dict[str, Any]]):
        if not self.network_model.is_healthy:
            return []
        return await asyncio.to_thread(self.network_model.analyze_suspicious_packets, packets)

