import asyncio
import logging
import io
from typing import Dict, Any
from pydantic import BaseModel
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
import socketio
import pandas as pd

from agentic_manager import AgenticManager
from auth_utils import verify_password, get_password_hash, create_access_token, decode_access_token, timedelta, ACCESS_TOKEN_EXPIRE_MINUTES
from database import engine, Base, get_db, SessionLocal
import db_models
from sqlalchemy.orm import Session
import crypto_utils

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="SentinelForge Secure Endpoint")

sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
socket_app = socketio.ASGIApp(sio, other_asgi_app=app)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def verify_token(token: str = Depends(oauth2_scheme)):
    decoded = decode_access_token(token)
    if not decoded:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return decoded.get("sub")

# Mock DB for demonstration
MOCK_ADMIN_HASH = get_password_hash("admin123")

class Token(BaseModel):
    access_token: str
    token_type: str
    session_key: str

# E2E Encryption stores
active_session_keys: Dict[str, str] = {}
client_session_keys: Dict[str, str] = {}

# Define callback to pipe internal Agent alerts out to the WebSockets
async def broadcast_event(event_dict: dict):
    # Asynchronously persist critical events to SQLite 
    def save_to_db():
        with SessionLocal() as db:
            if event_dict.get("type") in ["THREAT", "SUPERVISOR"] or "Threat" in event_dict.get("detail", ""):
                alert = db_models.ThreatAlert(
                    node_id=event_dict.get("node_id", "GLOBAL_NET"),
                    model_source=event_dict.get("model", "SYS"),
                    detail=event_dict.get("detail", "")
                )
                db.add(alert)
                db.commit()
            elif event_dict.get("type") == "AUDIT_RESULT":
                audit = db_models.AuditLog(
                    node_id="GLOBAL_ENV",
                    compliance_score=event_dict.get("score", 100),
                    detail="Automated Audit Sweep Completed"
                )
                db.add(audit)
                db.commit()
    
    if event_dict.get("type") in ["THREAT", "AUDIT_RESULT", "SUPERVISOR"] or "Threat" in event_dict.get("detail", ""):
        await asyncio.to_thread(save_to_db)

    await sio.emit('dashboard_events', event_dict)

agentic_manager = AgenticManager(callback_func=broadcast_event)

@app.on_event("startup")
async def startup_event():
    # Spin up SQLite tables if missing
    Base.metadata.create_all(bind=engine)
    
    # Load dynamic configurations from DB
    with SessionLocal() as db:
        configs = db.query(db_models.ModelConfig).all()
        
        # Group configs by agent
        agent_configs = {}
        for c in configs:
            if c.agent_name not in agent_configs:
                agent_configs[c.agent_name] = {}
            agent_configs[c.agent_name][c.parameter] = c.value
            
        for agent_name, config_dict in agent_configs.items():
            await agentic_manager.update_agent_config(agent_name, config_dict)
            
        # Load Phase 13 granular model toggles
        node_states = db.query(db_models.NodeModelState).all()
        for ns in node_states:
            agentic_manager.update_node_model_state(ns.node_id, ns.model_name, ns.is_active)
    
    # Start the 24/7 Engine
    asyncio.create_task(agentic_manager.start())

@app.on_event("shutdown")
async def shutdown_event():
    await agentic_manager.stop()

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username != "admin" or not verify_password(form_data.password, MOCK_ADMIN_HASH):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    
    session_key = crypto_utils.generate_session_key()
    active_session_keys[form_data.username] = session_key
    
    return {"access_token": access_token, "token_type": "bearer", "session_key": session_key}

@app.get("/api/history")
def get_historical_data(db: Session = Depends(get_db)):
    """Fetch recent alerts for dashboard hydration."""
    threats = db.query(db_models.ThreatAlert).order_by(db_models.ThreatAlert.timestamp.desc()).limit(10).all()
    latest_audit = db.query(db_models.AuditLog).order_by(db_models.AuditLog.timestamp.desc()).first()
    
    return {
        "threats": threats,
        "audit_score": latest_audit.compliance_score if latest_audit else 100
    }

@app.get("/api/export/report")
def export_excel_report(db: Session = Depends(get_db)):
    """Generate a multi-sheet Excel report of historical alerts and audits."""
    # Fetch Data
    threats = db.query(db_models.ThreatAlert).order_by(db_models.ThreatAlert.timestamp.desc()).limit(100).all()
    audits = db.query(db_models.AuditLog).order_by(db_models.AuditLog.timestamp.desc()).limit(100).all()

    # Convert to DataFrames
    threats_df = pd.DataFrame([{
        "Timestamp": t.timestamp,
        "Node ID": t.node_id,
        "Detection Model": t.model_source,
        "Threat Detail": t.detail
    } for t in threats])

    audits_df = pd.DataFrame([{
        "Timestamp": a.timestamp,
        "Global Score": a.compliance_score,
        "Audit Detail": a.detail
    } for a in audits])

    # Write to Memory Buffer
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        threats_df.to_excel(writer, sheet_name='Threat Alerts', index=False)
        audits_df.to_excel(writer, sheet_name='Audit Logs', index=False)
    
    output.seek(0)
    
    headers = {
        'Content-Disposition': 'attachment; filename="SentinelForge_Threat_Report.xlsx"'
    }
    
    return StreamingResponse(
        output, 
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", 
        headers=headers
    )

class ConfigPayload(BaseModel):
    parameter: str
    value: float

@app.get("/api/agents/config")
def get_all_configs(db: Session = Depends(get_db)):
    """Fetch all persisted model configurations."""
    configs = db.query(db_models.ModelConfig).all()
    return [{"agent_name": c.agent_name, "parameter": c.parameter, "value": c.value} for c in configs]

@app.post("/api/agents/config/{agent_name}")
async def update_config(agent_name: str, payload: ConfigPayload, db: Session = Depends(get_db)):
    """Update a model's running configuration and persist it to SQLite."""
    # Persist to DB
    existing = db.query(db_models.ModelConfig).filter(
        db_models.ModelConfig.agent_name == agent_name,
        db_models.ModelConfig.parameter == payload.parameter
    ).first()
    
    if existing:
        existing.value = payload.value
    else:
        new_conf = db_models.ModelConfig(agent_name=agent_name, parameter=payload.parameter, value=payload.value)
        db.add(new_conf)
    db.commit()

    # Hot-swap live Python objects
    await agentic_manager.update_agent_config(agent_name, {payload.parameter: payload.value})
    
    await broadcast_event({
        "type": "INFO",
        "model": "ADMIN",
        "detail": f"Updated AI Config: {agent_name} -> {payload.parameter} = {payload.value}"
    })
    
    return {"status": "success"}

@app.get("/api/nodes/{node_id}/models")
def get_node_model_states(node_id: str, username: str = Depends(verify_token), db: Session = Depends(get_db)):
    """Fetch the active models for a specific node."""
    states = db.query(db_models.NodeModelState).filter_by(node_id=node_id).all()
    # If no state is inserted yet, default in UI is True
    state_dict = { s.model_name: s.is_active for s in states }
    return {"node_id": node_id, "models": state_dict}

class TogglePayload(BaseModel):
    is_active: bool

@app.post("/api/nodes/{node_id}/models/{model_name}/toggle")
def toggle_node_model(node_id: str, model_name: str, payload: TogglePayload, username: str = Depends(verify_token), db: Session = Depends(get_db)):
    """Toggles a specific agent processing for a specific node."""
    state = db.query(db_models.NodeModelState).filter_by(node_id=node_id, model_name=model_name).first()
    
    if not state:
        state = db_models.NodeModelState(node_id=node_id, model_name=model_name, is_active=payload.is_active)
        db.add(state)
    else:
        state.is_active = payload.is_active
    db.commit()
    
    # Update active memory
    agentic_manager.update_node_model_state(node_id, model_name, payload.is_active)
    return {"status": "success", "is_active": payload.is_active}

@app.post("/api/quarantine/{node_id}")
async def quarantine_node(node_id: str):
    """Simulate OS-level iptables or Windows Firewall network drop."""
    logger.warning(f"OS FIREWALL HOOK TRIGGERED: Dropping all inbound/outbound TCP for {node_id}")
    
    await broadcast_event({
        "type": "INFO",
        "model": "ADMIN",
        "detail": f"Quarantine sequence executed on {node_id}. Internal Network interfaces locked."
    })
    return {"status": "quarantined", "node": node_id}

@app.post("/api/resolve/{node_id}")
async def resolve_node_threat(node_id: str):
    """Trigger the LLM Supervisor to autonomously write and execute a remediation patch."""
    logger.info(f"Autonomous Resolution requested for {node_id}")
    # Hand off to the 24/7 Agent Manager to stream the script generation over Websockets
    asyncio.create_task(agentic_manager.trigger_autonomous_resolution(node_id))
    return {"status": "resolving", "node": node_id}

@sio.event
async def connect(sid, environ, auth):
    """Secure connection verifying JWT token passed in WS handshake."""
    logger.info(f"Socket connection attempt: {sid}")
    token = auth.get('token') if auth else None
    
    decoded = decode_access_token(token) if token else None
    if not token or not decoded:
        logger.warning("Rejected unauthorized socket connection.")
        raise socketio.exceptions.ConnectionRefusedError('Authentication failed')
    
    username = decoded.get("sub")
    session_key = active_session_keys.get(username)
    if session_key:
        client_session_keys[sid] = session_key
        
    await sio.emit('dashboard_events', {'type': 'INFO', 'source': 'SYS', 'detail': 'Connected securely to SentinelForge Agentic Manager'})

@sio.event
async def disconnect(sid):
    if sid in client_session_keys:
        del client_session_keys[sid]
    logger.info(f"Client disconnected: {sid}")

@sio.event
async def trigger_audit(sid, data: Dict[str, Any]):
    logger.info(f"Manual Audit Triggered by Client {sid}")
    await agentic_manager.trigger_audit()

@sio.event
async def agent_command(sid, data: Dict[str, Any]):
    """Receives interactive text queries and commands from the dashboard Terminal."""
    
    command_str = ""
    # Check for E2E Encryption
    if "cipherText" in data and "iv" in data:
        session_key = client_session_keys.get(sid)
        if session_key:
            try:
                command_str = crypto_utils.decrypt_message(session_key, data["iv"], data["cipherText"])
                logger.info("Successfully decrypted command via E2E Tunnel.")
            except Exception as e:
                logger.error(f"Failed to decrypt admin command: {str(e)}")
                await broadcast_event({"type": "ERROR", "model": "ADMIN", "detail": "E2E Decryption Error. Bad Session Key."})
                return
        else:
            logger.warning("Received encrypted command but no session key found for client.")
            return
    else:
        # Fallback for plain text (to phase out later)
        command_str = data.get("command", "")
        
    command_str = command_str.strip()
    if command_str:
        logger.info(f"Admin Command Received: {command_str}")
        await agentic_manager.handle_admin_command(command_str)
