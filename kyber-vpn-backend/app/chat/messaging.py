"""
Implementación del sistema de mensajería segura para Kyber VPN.

Este módulo gestiona la mensajería entre usuarios, verificando que estén
conectados a través de la VPN y utilizando cifrado post-cuántico.
"""
import asyncio
import json
import uuid
import logging
from typing import Dict, List, Set, Optional, Any
from datetime import datetime
import ipaddress

from app.crypto.kyber import KyberManager
from app.crypto.symmetric import AESGCMCipher
from app.models.schemas import Message, User, ChatRoom
from app.core.config import settings
from app.core.security import create_access_token, get_password_hash, verify_password

# Configurar logger
logger = logging.getLogger(__name__)

class MessagingService:
    """Servicio de mensajería segura para usuarios de la VPN."""
    
    def __init__(self):
        """Inicializa el servicio de mensajería."""
        self.connected_users: Dict[str, User] = {}  # username -> user
        self.user_sessions: Dict[str, str] = {}  # session_id -> username
        self.vpn_sessions: Dict[str, str] = {}  # vpn_ip -> username
        self.user_key_pairs: Dict[str, Dict] = {}  # username -> keypair
        self.chat_rooms: Dict[str, ChatRoom] = {}  # room_id -> room
        self.active_connections: Dict[str, Set] = {}  # room_id -> set of websockets
        
        # Datos de usuario simulados (en producción, usaríamos una base de datos)
        self._users_db = {
            "usuario1": {
                "username": "usuario1",
                "display_name": "Usuario Demo 1",
                "hashed_password": get_password_hash("password1")
            },
            "usuario2": {
                "username": "usuario2",
                "display_name": "Usuario Demo 2",
                "hashed_password": get_password_hash("password2")
            }
        }
        
        # Crear una sala de chat predeterminada
        self._create_default_room()
        
        logger.info("Servicio de mensajería inicializado")
    
    def _create_default_room(self):
        """Crea una sala de chat predeterminada para todos los usuarios."""
        default_room = ChatRoom(
            id="general",
            name="Canal General",
            participants=list(self._users_db.keys()),
            is_group=True
        )
        self.chat_rooms["general"] = default_room
        self.active_connections["general"] = set()
    
    async def register_user(self, username: str, password: str, display_name: str) -> Dict[str, Any]:
        """
        Registra un nuevo usuario en el sistema.
        
        Args:
            username: Nombre de usuario
            password: Contraseña
            display_name: Nombre para mostrar
            
        Returns:
            Resultado del registro
        """
        # Verificar si el usuario ya existe
        if username in self._users_db:
            return {"success": False, "message": "El nombre de usuario ya está en uso"}
        
        # Crear hash de la contraseña
        hashed_password = get_password_hash(password)
        
        # Almacenar usuario en la "base de datos"
        self._users_db[username] = {
            "username": username,
            "display_name": display_name,
            "hashed_password": hashed_password
        }
        
        # Añadir usuario a la sala predeterminada
        if "general" in self.chat_rooms:
            room = self.chat_rooms["general"]
            if username not in room.participants:
                room.participants.append(username)
        
        logger.info(f"Usuario registrado: {username}")
        return {"success": True, "message": "Usuario registrado correctamente"}
    
    async def authenticate_user(self, username: str, password: str, vpn_ip: str) -> Dict[str, Any]:
        """
        Autentica a un usuario y verifica que esté conectado a través de la VPN.
        
        Args:
            username: Nombre de usuario
            password: Contraseña del usuario
            vpn_ip: Dirección IP asignada dentro de la VPN
            
        Returns:
            Resultado de la autenticación con token de sesión
        """
        # Verificar que la IP pertenezca al rango de la VPN
        try:
            ip = ipaddress.ip_address(vpn_ip)
            vpn_network = ipaddress.ip_network(settings.VPN_SUBNET)
            if ip not in vpn_network:
                logger.warning(f"Intento de autenticación desde IP fuera de la VPN: {vpn_ip}")
                return {
                    "success": False, 
                    "message": "Autenticación solo permitida a través de la VPN", 
                    "token": None
                }
        except ValueError:
            return {"success": False, "message": "Dirección IP inválida", "token": None}
        
        # Verificar credenciales
        user_data = self._users_db.get(username)
        if not user_data:
            return {"success": False, "message": "Usuario no encontrado", "token": None}
        
        if not verify_password(password, user_data["hashed_password"]):
            logger.warning(f"Intento de autenticación fallido para usuario: {username}")
            return {"success": False, "message": "Credenciales incorrectas", "token": None}
        
        # Crear token JWT
        session_id = str(uuid.uuid4())
        token_data = {
            "sub": username,
            "session_id": session_id,
            "vpn_ip": vpn_ip
        }
        token = create_access_token(token_data)
        
        # Almacenar sesión
        self.user_sessions[session_id] = username
        self.vpn_sessions[vpn_ip] = username
        
        # Crear usuario si no existe
        if username not in self.connected_users:
            self.connected_users[username] = User(
                username=username,
                display_name=user_data["display_name"],
                is_online=True,
                vpn_ip=vpn_ip,
                last_seen=datetime.now()
            )
        else:
            # Actualizar estado
            user = self.connected_users[username]
            user.is_online = True
            user.vpn_ip = vpn_ip
        
        logger.info(f"Usuario autenticado: {username} desde IP VPN: {vpn_ip}")
        
        return {
            "success": True,
            "message": "Autenticación exitosa",
            "token": token,
            "user_data": {
                "username": username,
                "display_name": user_data["display_name"]
            }
        }
    
    async def get_user_rooms(self, username: str) -> List[Dict[str, Any]]:
        """
        Obtiene las salas de chat a las que pertenece un usuario.
        
        Args:
            username: Nombre del usuario
            
        Returns:
            Lista de salas de chat
        """
        if username not in self._users_db:
            return []
        
        rooms = []
        for room_id, room in self.chat_rooms.items():
            if username in room.participants:
                rooms.append({
                    "id": room.id,
                    "name": room.name,
                    "is_group": room.is_group,
                    "participants": room.participants,
                    "created_at": room.created_at.isoformat()
                })
        
        return rooms
    
    async def get_room_messages(self, room_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Obtiene los mensajes recientes de una sala de chat.
        
        Args:
            room_id: ID de la sala
            limit: Número máximo de mensajes a obtener
            
        Returns:
            Lista de mensajes
        """
        # En una implementación real, estos mensajes vendrían de una base de datos
        # Aquí simulamos algunos mensajes de ejemplo
        sample_messages = [
            {
                "id": str(uuid.uuid4()),
                "sender": "usuario1",
                "room_id": room_id,
                "content": "Hola a todos, ¿cómo están?",
                "timestamp": (datetime.now().replace(minute=0, second=0)).isoformat(),
                "read_by": ["usuario1"]
            },
            {
                "id": str(uuid.uuid4()),
                "sender": "usuario2",
                "room_id": room_id,
                "content": "Todo bien por aquí, la conexión VPN está funcionando muy bien",
                "timestamp": (datetime.now().replace(minute=5, second=30)).isoformat(),
                "read_by": ["usuario1", "usuario2"]
            },
            {
                "id": str(uuid.uuid4()),
                "sender": "usuario1",
                "room_id": room_id,
                "content": "¡Excelente! La criptografía post-cuántica hace que sea muy seguro",
                "timestamp": (datetime.now().replace(minute=10, second=15)).isoformat(),
                "read_by": ["usuario1"]
            }
        ]
        
        return sample_messages[:limit]
    
    async def create_message(self, session_id: str, room_id: str, content: str) -> Optional[Dict[str, Any]]:
        """
        Crea un nuevo mensaje en una sala de chat.
        
        Args:
            session_id: ID de sesión del remitente
            room_id: ID de la sala de chat
            content: Contenido del mensaje
            
        Returns:
            Mensaje creado o None si hay error
        """
        # Verificar sesión válida
        username = self.user_sessions.get(session_id)
        if not username:
            logger.warning(f"Intento de enviar mensaje con sesión inválida: {session_id}")
            return None
        
        # Verificar que la sala exista
        if room_id not in self.chat_rooms:
            logger.warning(f"Intento de enviar mensaje a sala inexistente: {room_id}")
            return None
        
        # Verificar pertenencia a la sala
        room = self.chat_rooms[room_id]
        if username not in room.participants:
            logger.warning(f"Usuario {username} intenta enviar mensaje a sala {room_id} a la que no pertenece")
            return None
        
        # Crear mensaje (en una implementación real, lo cifraríamos con AES)
        message_id = str(uuid.uuid4())
        timestamp = datetime.now()
        
        message = {
            "id": message_id,
            "sender": username,
            "room_id": room_id,
            "content": content,
            "timestamp": timestamp.isoformat(),
            "read_by": [username]
        }
        
        logger.info(f"Mensaje enviado por {username} a sala {room_id}")
        return message
    
    async def create_secure_channel(self, user1: str, user2: str) -> Dict[str, Any]:
        """
        Crea un canal seguro entre dos usuarios usando intercambio Kyber.
        
        Args:
            user1: Primer usuario
            user2: Segundo usuario
            
        Returns:
            Información del canal creado
        """
        # Verificar que los usuarios existan
        if user1 not in self._users_db or user2 not in self._users_db:
            return {"success": False, "message": "Uno o ambos usuarios no existen"}
        
        # Generar ID para la sala
        room_id = f"private_{user1}_{user2}_{str(uuid.uuid4())[:8]}"
        
        # Crear instancia de Kyber para intercambio de claves
        kyber = KyberManager()
        
        # Generar par de claves para el intercambio
        key_pair = kyber.generate_keypair()
        
        # En una implementación real, aquí realizaríamos el intercambio
        # de claves Kyber entre los usuarios
        
        # Crear sala de chat privada
        room = ChatRoom(
            id=room_id,
            name=f"Chat privado: {user1} - {user2}",
            participants=[user1, user2],
            is_group=False,
            encryption_key=key_pair["public_key"]  # Simplificado para demo
        )
        
        # Almacenar sala
        self.chat_rooms[room_id] = room
        self.active_connections[room_id] = set()
        
        logger.info(f"Canal seguro creado entre {user1} y {user2}")
        
        return {
            "success": True,
            "room_id": room_id,
            "name": room.name
        }

# Instancia global del servicio de mensajería
messaging_service = MessagingService()