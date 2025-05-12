"""
Rutas de la API para el sistema de mensajería.

Este módulo implementa los endpoints para el registro, autenticación,
y comunicación en tiempo real entre usuarios de la VPN.
"""
import json
import logging
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from app.chat.messaging import messaging_service
from app.models.schemas import User, Message, ChatRoom, UserAuthRequest, UserAuthResponse
from app.core.security import verify_token

# Configurar logger
logger = logging.getLogger(__name__)

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/chat/login")

# Conexiones WebSocket activas por sesión
active_connections: Dict[str, WebSocket] = {}

# Dependencia para obtener usuario actual mediante token
async def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    username = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"username": username, "session_id": payload.get("session_id")}

@router.post("/register", response_model=Dict[str, Any])
async def register_user(username: str, password: str, display_name: str):
    """Registra un nuevo usuario en el sistema de mensajería."""
    return await messaging_service.register_user(username, password, display_name)

@router.post("/login", response_model=UserAuthResponse)
async def login_user(request: UserAuthRequest):
    """
    Autentica a un usuario y verifica que esté conectado a través de la VPN.
    
    Solo permite el acceso si el usuario está conectado a través de la VPN.
    """
    return await messaging_service.authenticate_user(
        request.username, 
        request.password, 
        request.vpn_ip
    )

@router.get("/rooms", response_model=List[Dict[str, Any]])
async def get_user_rooms(current_user: Dict = Depends(get_current_user)):
    """Obtiene las salas de chat a las que pertenece el usuario."""
    username = current_user["username"]
    return await messaging_service.get_user_rooms(username)

@router.get("/rooms/{room_id}/messages", response_model=List[Dict[str, Any]])
async def get_room_messages(
    room_id: str, 
    limit: int = Query(50, ge=1, le=100),
    current_user: Dict = Depends(get_current_user)
):
    """Obtiene los mensajes recientes de una sala de chat."""
    return await messaging_service.get_room_messages(room_id, limit)

@router.post("/rooms/private", response_model=Dict[str, Any])
async def create_private_room(
    other_username: str,
    current_user: Dict = Depends(get_current_user)
):
    """Crea una sala de chat privada entre dos usuarios."""
    username = current_user["username"]
    return await messaging_service.create_secure_channel(username, other_username)

@router.websocket("/ws/{session_id}")
async def chat_websocket(websocket: WebSocket, session_id: str):
    """
    Endpoint WebSocket para comunicación en tiempo real.
    
    Este endpoint maneja la comunicación bidireccional para
    el servicio de mensajería de la VPN.
    """
    # Verificar que la sesión es válida
    if session_id not in messaging_service.user_sessions:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        logger.warning(f"Intento de conexión WebSocket con sesión inválida: {session_id}")
        return
        
    username = messaging_service.user_sessions[session_id]
    
    # Aceptar la conexión WebSocket
    await websocket.accept()
    logger.info(f"Conexión WebSocket aceptada para usuario: {username}")
    
    # Almacenar conexión activa
    active_connections[session_id] = websocket
    
    # Notificar a todos los usuarios que este usuario está en línea
    user = messaging_service.connected_users.get(username)
    if user:
        user.is_online = True
        # En una implementación real, notificaríamos a los demás usuarios
    
    try:
        # Bucle principal de recepción de mensajes
        while True:
            # Recibir mensaje del cliente
            data = await websocket.receive_text()
            message_data = json.loads(data)
            
            # Procesar diferentes tipos de mensajes
            if message_data["type"] == "message":
                # Enviar mensaje a sala de chat
                message = await messaging_service.create_message(
                    session_id=session_id,
                    room_id=message_data["room_id"],
                    content=message_data["content"]
                )
                
                if message:
                    # Enviar confirmación al remitente
                    await websocket.send_text(json.dumps({
                        "type": "message_sent",
                        "message_id": message["id"],
                        "timestamp": message["timestamp"]
                    }))
                    
                    # Distribuir mensaje a todos los participantes de la sala
                    await broadcast_to_room(message)
                else:
                    # Enviar error al remitente
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "No se pudo enviar el mensaje"
                    }))
            
            elif message_data["type"] == "typing":
                # Notificar que el usuario está escribiendo
                room_id = message_data.get("room_id")
                if room_id and room_id in messaging_service.chat_rooms:
                    await broadcast_to_room({
                        "type": "typing",
                        "room_id": room_id,
                        "username": username
                    }, exclude_session=session_id)
    
    except WebSocketDisconnect:
        # Manejar desconexión del cliente
        logger.info(f"WebSocket desconectado para usuario: {username}")
        if session_id in active_connections:
            del active_connections[session_id]
        
        if username in messaging_service.connected_users:
            user = messaging_service.connected_users[username]
            user.is_online = False
            # En una implementación real, notificaríamos a los demás usuarios
    
    except Exception as e:
        logger.error(f"Error en WebSocket para usuario {username}: {str(e)}")
        if session_id in active_connections:
            del active_connections[session_id]

async def broadcast_to_room(message: Dict[str, Any], exclude_session: Optional[str] = None):
    """
    Envía un mensaje a todos los participantes de una sala.
    
    Args:
        message: Mensaje a enviar
        exclude_session: Sesión a excluir del broadcast (opcional)
    """
    if "room_id" not in message:
        return
    
    room_id = message["room_id"]
    if room_id not in messaging_service.chat_rooms:
        return
    
    room = messaging_service.chat_rooms[room_id]
    for participant in room.participants:
        # Buscar sesiones activas del participante
        for session_id, username in messaging_service.user_sessions.items():
            if username == participant and session_id in active_connections and session_id != exclude_session:
                websocket = active_connections[session_id]
                try:
                    await websocket.send_text(json.dumps({
                        "type": "new_message",
                        "message": message
                    }))
                except Exception as e:
                    logger.error(f"Error enviando mensaje a {username}: {str(e)}")