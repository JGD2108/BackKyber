"""
Rutas de la API para gestión de conexiones VPN.

Este módulo implementa los endpoints para conectar/desconectar
la VPN y obtener su estado actual.
"""
from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any

from app.models.schemas import ConnectionRequest, ConnectionResponse, VpnStatus
from app.network.vpn import VPNManager

# Creamos una instancia global del gestor VPN
# En una aplicación real, esto podría gestionarse con inyección de dependencias
vpn_manager = VPNManager()

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
    result = await vpn_manager.connect(request.serverId)
    
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
    result = await vpn_manager.disconnect()
    
    return ConnectionResponse(
        success=result["success"],
        message=result["message"],
        vpnIp=None
    )

@router.get("/status", response_model=VpnStatus)
async def get_vpn_status():
    """
    Obtiene el estado actual de la conexión VPN.
    
    Returns:
        Estado actual de la VPN
    """
    return await vpn_manager.get_status()
