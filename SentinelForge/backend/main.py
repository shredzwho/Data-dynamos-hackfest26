import asyncio
import logging
from typing import Dict, Any
from pydantic import BaseModel, conint
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
import socketio

from agentic_manager import AgenticManager
from auth_utils import verify_password, get_password_hash, create_access_token, decode_access_token, timedelta, ACCESS_TOKEN_EXPIRE_MINUTES

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

agentic_manager = AgenticManager()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Mock DB for demonstration
MOCK_ADMIN_HASH = get_password_hash("admin123")

class Token(BaseModel):
    access_token: str
    token_type: str

class PacketSchema(BaseModel):
    packet_id: str
    source_ip: str
    dest_ip: str
    protocol: str
    size: conint(ge=0, le=65535)

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
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/health")
async def health_check():
    statuses = await agentic_manager.run_health_checks()
    return {"status": "ok", "models": statuses}

@sio.event
async def connect(sid, environ, auth):
    """Secure connection verifying JWT token passed in WS handshake."""
    logger.info(f"Socket connection attempt: {sid}")
    token = auth.get('token') if auth else None
    
    if not token or not decode_access_token(token):
        logger.warning("Rejected unauthorized socket connection.")
        raise socketio.exceptions.ConnectionRefusedError('Authentication failed')
        
    await sio.emit('system_status', {'message': 'Connected securely to SentinelForge Agentic Manager'})

@sio.event
async def disconnect(sid):
    logger.info(f"Client disconnected: {sid}")

@sio.event
async def dashboard_join(sid, data: Dict[str, Any]):
    logger.info(f"Secure Client {sid} joined dashboard updates.")
    await sio.enter_room(sid, "dashboard")
    await sio.emit('threats_update', {'message': 'Real-time threat monitoring initialized.'}, room="dashboard")
    await sio.emit('resource_update', {'cpu': 15, 'ram': 45, 'disk': 10}, room="dashboard")

@sio.event
async def simulate_packet(sid, data: Dict[str, Any]):
    try:
        # Strict Pydantic Validation on incoming WS Packet data
        packet_data = PacketSchema(**data.get("packet", {}))
    except Exception as e:
        logger.error(f"Malformed packet discarded: {e}")
        return

    results = await agentic_manager.ingest_network_packets([packet_data.model_dump()])
    for result in results:
        if result.get("is_threat"):
            alert = {
                "id": result.get("packet_id"),
                "type": "Network Anomaly",
                "severity": "High",
                "probability": result.get("threat_probability")
            }
            await sio.emit('new_threat_alert', alert, room="dashboard")
