"""
Rutas de la API para gestión de conexiones VPN.

Este módulo implementa los endpoints para conectar/desconectar
la VPN y obtener su estado actual.
"""
from asyncio.log import logger
from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any
import logging
import asyncio

from app.models.schemas import ConnectionRequest, ConnectionResponse, VpnStatus
from app.network.vpn_client import vpn_client  # Usar la implementación real
from app.core.config import settings

logger = logging.getLogger("kyber-vpn")

router = APIRouter()
# Añadir logs detallados para diagnóstico
@router.post("/connect")
async def connect_to_vpn(request: ConnectionRequest):
    """
    Establece una conexión VPN con el servidor especificado.
    
    Args:
        request: Datos de la conexión que incluyen el ID del servidor
        
    Returns:
        Resultado de la operación de conexión
    """
    logger.info(f"Intentando conectar a VPN con servidor: {request.serverId}")
    
    # Track Azure-specific connection attempts
    is_azure_client = False
    try:
        # Check for Azure-specific headers that NGINX adds
        if request.headers.get("x-azure-client") == "true":
            is_azure_client = True
            logger.info("Conexión desde cliente Azure detectada")
    except:
        pass
        
    try:
        # Add more detailed logging for Azure troubleshooting
        logger.info(f"Buscando servidor con ID: {request.serverId}")
        available_servers = [s.get("id") for s in settings.VPN_SERVERS]
        logger.info(f"Servidores disponibles: {available_servers}")
        
        server = next((s for s in settings.VPN_SERVERS if s["id"] == request.serverId), None)
        if not server:
            logger.error(f"Servidor no encontrado: {request.serverId}")
            raise HTTPException(status_code=404, detail="Servidor no encontrado")
        
        logger.info(f"Conectando a {server['ip']}:{server['port']}")
        
        # Add retry logic for Azure connections
        max_retries = 3 if is_azure_client else 1
        retry_count = 0
        last_error = None
        
        while retry_count < max_retries:
            try:
                result = await vpn_client.connect(server["ip"], server["port"])
                
                if not result["success"]:
                    logger.error(f"Conexión fallida: {result['message']}")
                else:
                    logger.info(f"Conexión exitosa. IP VPN asignada: {result.get('vpn_ip')}")
                
                return ConnectionResponse(**result)
            except Exception as e:
                retry_count += 1
                last_error = e
                logger.warning(f"Intento {retry_count} fallido: {str(e)}")
                if retry_count < max_retries:
                    await asyncio.sleep(1)  # Wait before retrying
        
        # If we get here, all retries failed
        raise last_error
        
    except Exception as e:
        logger.error(f"Error en conexión VPN: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error interno al conectar: {str(e)}")

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
