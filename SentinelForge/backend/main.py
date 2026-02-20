import asyncio
import logging
from typing import Dict, Any
from pydantic import BaseModel
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

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Mock DB for demonstration
MOCK_ADMIN_HASH = get_password_hash("admin123")

class Token(BaseModel):
    access_token: str
    token_type: str

# Define callback to pipe internal Agent alerts out to the WebSockets
async def broadcast_event(event_dict: dict):
    await sio.emit('dashboard_events', event_dict)

agentic_manager = AgenticManager(callback_func=broadcast_event)

@app.on_event("startup")
async def startup_event():
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
    return {"access_token": access_token, "token_type": "bearer"}

@sio.event
async def connect(sid, environ, auth):
    """Secure connection verifying JWT token passed in WS handshake."""
    logger.info(f"Socket connection attempt: {sid}")
    token = auth.get('token') if auth else None
    
    if not token or not decode_access_token(token):
        logger.warning("Rejected unauthorized socket connection.")
        raise socketio.exceptions.ConnectionRefusedError('Authentication failed')
        
    await sio.emit('dashboard_events', {'type': 'INFO', 'source': 'SYS', 'detail': 'Connected securely to SentinelForge Agentic Manager'})

@sio.event
async def disconnect(sid):
    logger.info(f"Client disconnected: {sid}")

@sio.event
async def trigger_audit(sid, data: Dict[str, Any]):
    logger.info(f"Manual Audit Triggered by Client {sid}")
    await agentic_manager.trigger_audit()
