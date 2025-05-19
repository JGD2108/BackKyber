"""
Rutas de la API para gestión de conexiones VPN.

Este módulo implementa los endpoints para conectar/desconectar
la VPN y obtener su estado actual.
"""
from asyncio.log import logger
from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any

from app.models.schemas import ConnectionRequest, ConnectionResponse, VpnStatus
from app.network.vpn_client import vpn_client  # Usar la implementación real
from app.core.config import settings

router = APIRouter()
# Añadir logs detallados para diagnóstico
@router.post("/connect")
async def connect_to_vpn(request: ConnectionRequest):
    logger.info(f"Intentando conectar a VPN con servidor: {request.serverId}")
    
    try:
        server = next((s for s in settings.VPN_SERVERS if s["id"] == request.serverId), None)
        if not server:
            logger.error(f"Servidor no encontrado: {request.serverId}")
            raise HTTPException(status_code=404, detail="Servidor no encontrado")
        
        logger.info(f"Conectando a {server['ip']}:{server['port']}")
        result = await vpn_client.connect(server["ip"], server["port"])
        
        if not result["success"]:
            logger.error(f"Conexión fallida: {result['message']}")
        
        return ConnectionResponse(**result)
    except Exception as e:
        logger.error(f"Error en conexión VPN: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Error interno al conectar")

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
