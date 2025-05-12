"""
Rutas de la API para gestión de conexiones VPN.

Este módulo implementa los endpoints para conectar/desconectar
la VPN y obtener su estado actual.
"""
from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any

from app.models.schemas import ConnectionRequest, ConnectionResponse, VpnStatus
from app.network.vpn_client import vpn_client  # Usar la implementación real

router = APIRouter()

@router.post("/connect", response_model=ConnectionResponse)
async def connect_to_vpn(request: ConnectionRequest):
    """
    Establece una conexión VPN con el servidor especificado.
    
    Args:
        request: Solicitud con el ID del servidor
        
    Returns:
        Resultado de la operación de conexión
    """
    # Buscar información del servidor
    from app.core.config import settings
    
    server = None
    for s in settings.VPN_SERVERS:
        if s["id"] == request.serverId:
            server = s
            break
    
    if not server:
        raise HTTPException(status_code=404, detail=f"Servidor con ID {request.serverId} no encontrado")
    
    # Conectar usando la implementación real
    result = await vpn_client.connect(server["ip"], server["port"])
    
    return ConnectionResponse(
        success=result["success"],
        message=result["message"],
        vpnIp=result.get("vpnIp")
    )

@router.post("/disconnect", response_model=ConnectionResponse)
async def disconnect_from_vpn():
    """
    Finaliza la conexión VPN actual.
    
    Returns:
        Resultado de la operación de desconexión
    """
    result = await vpn_client.disconnect()
    
    return ConnectionResponse(
        success=result["success"],
        message=result["message"],
        vpnIp=None
    )

@router.get("/status")
async def get_vpn_status():
    """
    Obtiene el estado actual de la conexión VPN.
    """
    return vpn_client.get_status()
