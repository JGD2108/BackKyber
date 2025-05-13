"""
Rutas de la API para gestión de conexiones VPN con soporte para Azure.
"""
from fastapi import APIRouter, HTTPException, Depends, Request
from typing import Dict, Any
import logging
from app.models.schemas import ConnectionRequest, ConnectionResponse, VpnStatus
from app.network.vpn_client import vpn_client
from app.core.config import settings

# Set up logging with Azure-friendly format
logger = logging.getLogger("kyber-vpn")

router = APIRouter()

@router.post("/connect", response_model=ConnectionResponse)
async def connect_to_vpn(request: ConnectionRequest, req: Request):
    """
    Establece una conexión VPN con el servidor especificado.
    """
    # Enhanced logging for Azure monitoring
    client_ip = req.client.host
    logger.info(f"Connection request from {client_ip} for server ID: '{request.serverId}'")
    
    # Debug: Log all settings.VPN_SERVERS details
    server_ids = [s.get("id", "UNKNOWN") for s in settings.VPN_SERVERS]
    logger.info(f"Available server IDs: {server_ids}")
    
    # Verify if VPN_SERVERS is properly populated
    if not settings.VPN_SERVERS:
        logger.error(f"ERROR: settings.VPN_SERVERS is empty! Value: {settings.VPN_SERVERS}")
        # Azure best practice: Return detailed error for troubleshooting
        raise HTTPException(
            status_code=500,
            detail="VPN server configuration not available. Please contact the administrator."
        )
    
    # Find server with case-insensitive matching for better UX
    server = None
    for s in settings.VPN_SERVERS:
        if s.get("id") and s.get("id").lower() == request.serverId.lower():
            server = s
            logger.info(f"Found matching server: {s.get('id')}")
            break
    
    if not server:
        logger.warning(f"Server ID '{request.serverId}' not found in VPN_SERVERS!")
        # Log all server data for debugging
        logger.debug(f"All VPN_SERVERS: {settings.VPN_SERVERS}")
        raise HTTPException(
            status_code=404,
            detail=f"Servidor con ID {request.serverId} no encontrado"
        )
    
    # Azure best practice: Log operation metrics
    logger.info(f"Attempting VPN connection to {server['ip']}:{server['port']}")
    
    # Connect to the VPN server
    try:
        result = await vpn_client.connect(server["ip"], server["port"])
        
        # Azure best practice: Log successful operations
        logger.info(f"VPN connection successful: {result.get('success')}")
        
        return ConnectionResponse(
            success=result["success"],
            message=result["message"],
            vpnIp=result.get("vpnIp")
        )
    except Exception as e:
        # Azure best practice: Enhanced error logging
        logger.error(f"VPN connection failed: {str(e)}", exc_info=True)
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
