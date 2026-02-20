from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime
from database import Base
import datetime

class ThreatAlert(Base):
    __tablename__ = "threat_alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    node_id = Column(String, index=True) # E.g. 'WS-ENT-05' or '10.0.1.55'
    model_source = Column(String)        # E.g. 'NET', 'WEB', 'MEM' (or 'SUPERVISOR')
    detail = Column(String)
    is_triaged = Column(Boolean, default=False)
    
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    node_id = Column(String, index=True)
    compliance_score = Column(Float)
    detail = Column(String)

class ModelConfig(Base):
    __tablename__ = "model_configs"
    
    id = Column(Integer, primary_key=True, index=True)
    agent_name = Column(String, index=True) # e.g. 'NET', 'LLM_SUPERVISOR'
    parameter = Column(String) # e.g. 'contamination', 'threat_threshold'
    value = Column(Float)

class NodeModelState(Base):
    __tablename__ = "node_model_states"
    
    id = Column(Integer, primary_key=True, index=True)
    node_id = Column(String, index=True) # e.g. 'WS-ENT-04'
    model_name = Column(String, index=True) # e.g. 'NET', 'LOG'
    is_active = Column(Boolean, default=True)
