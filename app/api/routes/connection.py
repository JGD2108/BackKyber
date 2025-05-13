"""
Rutas de la API para gestión de conexiones VPN.

Este módulo implementa los endpoints para conectar/desconectar
la VPN y obtener su estado actual.
"""
from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any

from app.models.schemas import ConnectionRequest, ConnectionResponse, VpnStatus
from app.network.vpn_client import vpn_client  # Usar la implementación real
from app.core.config import settings  # Import settings at the module level

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
    # Log the received server ID
    print(f"Backend: Received connect request for serverId: {request.serverId}")
    
    # Buscar información del servidor - ENSURE VPN_SERVERS IS PROPERLY POPULATED
    server = None
    
    # First, verify if VPN_SERVERS is populated at all
    if not settings.VPN_SERVERS:
        print(f"WARNING: settings.VPN_SERVERS is empty! Current value: {settings.VPN_SERVERS}")
        raise HTTPException(
            status_code=500, 
            detail="Configuración de servidores VPN no disponible. Contacte al administrador."
        )
    
    # Log all available server IDs for debugging
    available_ids = [s.get("id") for s in settings.VPN_SERVERS]
    print(f"Available server IDs: {available_ids}")
    
    for s in settings.VPN_SERVERS:
        if s.get("id") == request.serverId:
            server = s
            break
    
    if not server:
        print(f"ERROR: Server ID {request.serverId} not found in settings.VPN_SERVERS!")
        raise HTTPException(
            status_code=404, 
            detail=f"Servidor con ID {request.serverId} no encontrado"
        )
    
    # Conectar usando la implementación real
    try:
        result = await vpn_client.connect(server["ip"], server["port"])
        
        return ConnectionResponse(
            success=result["success"],
            message=result["message"],
            vpnIp=result.get("vpnIp")
        )
    except Exception as e:
        print(f"ERROR connecting to VPN: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error conectando a la VPN: {str(e)}"
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
