"""
Esquemas de datos para la API de Kyber VPN.

Este módulo define los modelos Pydantic utilizados para validar
y serializar datos en toda la aplicación.
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Set
from enum import Enum
from datetime import datetime

class ServerStatus(str, Enum):
    """Estado posible de un servidor VPN."""
    ONLINE = "online"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"

class ServerBase(BaseModel):
    """Modelo base para servidores VPN."""
    name: str = Field(..., description="Nombre descriptivo del servidor")
    location: str = Field(..., description="Ubicación geográfica del servidor")
    ip: str = Field(..., description="Dirección IP del servidor")
    port: int = Field(..., description="Puerto del servidor", gt=0, lt=65536)

class Server(ServerBase):
    """Modelo completo de un servidor VPN."""
    id: str = Field(..., description="Identificador único del servidor")
    status: ServerStatus = Field(default=ServerStatus.ONLINE, description="Estado actual del servidor")
    latency: int = Field(default=0, description="Latencia estimada en ms", ge=0)
    
    class Config:
        schema_extra = {
            "example": {
                "id": "server1",
                "name": "Servidor Madrid",
                "location": "Madrid, España",
                "ip": "192.168.1.100",
                "port": 1194,
                "status": "online",
                "latency": 25
            }
        }

class ConnectionRequest(BaseModel):
    """Solicitud para conectar a un servidor VPN."""
    serverId: str = Field(..., description="ID del servidor al que conectar")
    
    class Config:
        schema_extra = {
            "example": {
                "serverId": "server1"
            }
        }

class ConnectionResponse(BaseModel):
    """Respuesta a una solicitud de conexión VPN."""
    success: bool = Field(..., description="Indica si la operación fue exitosa")
    message: str = Field(..., description="Mensaje informativo")
    vpnIp: Optional[str] = Field(None, description="IP asignada al cliente en la VPN")
    
    class Config:
        schema_extra = {
            "example": {
                "success": True,
                "message": "Conexión establecida exitosamente",
                "vpnIp": "10.8.0.2"
            }
        }

class VpnStatus(BaseModel):
    """Estado actual de la conexión VPN."""
    connected: bool = Field(..., description="Indica si hay una conexión VPN activa")
    uptime: int = Field(default=0, description="Tiempo de conexión en segundos")
    bytesReceived: int = Field(default=0, description="Bytes recibidos")
    bytesSent: int = Field(default=0, description="Bytes enviados")
    latency: int = Field(default=0, description="Latencia actual en ms")
    vpnIp: Optional[str] = Field(None, description="IP asignada dentro de la VPN")
    server_id: Optional[str] = Field(None, description="ID del servidor conectado")
    
    class Config:
        schema_extra = {
            "example": {
                "connected": True,
                "uptime": 3600,
                "bytesReceived": 1048576,
                "bytesSent": 524288,
                "latency": 30,
                "vpnIp": "10.8.0.2",
                "server_id": "server1"
            }
        }

class EducationalContent(BaseModel):
    """Contenido educativo sobre criptografía post-cuántica."""
    title: str
    description: str
    sections: List[Dict[str, str]]
    additional_resources: Optional[List[Dict[str, str]]] = None

# Nuevos modelos para el sistema de mensajería
class User(BaseModel):
    """Usuario del sistema de mensajería."""
    username: str = Field(..., description="Nombre de usuario único")
    display_name: str = Field(..., description="Nombre para mostrar")
    is_online: bool = Field(default=False, description="Estado de conexión")
    last_seen: Optional[datetime] = Field(None, description="Última vez visto")
    vpn_ip: Optional[str] = Field(None, description="IP asignada en la VPN")

class Message(BaseModel):
    """Mensaje enviado en el chat."""
    id: str = Field(..., description="ID único del mensaje")
    sender: str = Field(..., description="Usuario que envía el mensaje")
    room_id: str = Field(..., description="Sala donde se envía el mensaje")
    content: str = Field(..., description="Contenido cifrado del mensaje")
    timestamp: datetime = Field(default_factory=datetime.now, description="Momento de envío")
    read_by: List[str] = Field(default_factory=list, description="Usuarios que han leído el mensaje")

class ChatRoom(BaseModel):
    """Sala de chat entre usuarios."""
    id: str = Field(..., description="ID único de la sala")
    name: Optional[str] = Field(None, description="Nombre de la sala para grupos")
    participants: List[str] = Field(..., description="Participantes en la sala")
    is_group: bool = Field(default=False, description="Si es una sala grupal")
    created_at: datetime = Field(default_factory=datetime.now, description="Momento de creación")
    encryption_key: Optional[str] = Field(None, description="Clave de cifrado compartida (cifrada)")

class UserAuthRequest(BaseModel):
    """Solicitud de autenticación de usuario."""
    username: str = Field(..., description="Nombre de usuario")
    password: str = Field(..., description="Contraseña")
    vpn_ip: str = Field(..., description="Dirección IP en la VPN")

class UserAuthResponse(BaseModel):
    """Respuesta a una solicitud de autenticación."""
    success: bool = Field(..., description="Si la autenticación fue exitosa")
    token: Optional[str] = Field(None, description="Token de sesión JWT")
    message: str = Field(..., description="Mensaje informativo")
    user_data: Optional[Dict[str, Any]] = Field(None, description="Datos del usuario autenticado")
