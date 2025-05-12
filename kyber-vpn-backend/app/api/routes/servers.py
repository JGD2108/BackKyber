"""
Rutas de la API para gestión de servidores VPN.

Este módulo implementa los endpoints relacionados con la consulta
de servidores VPN disponibles y su información.
"""
from fastapi import APIRouter, HTTPException
from typing import List

from app.core.config import settings
from app.models.schemas import Server, ServerStatus

router = APIRouter()

@router.get("/", response_model=List[Server])
async def get_servers():
    """
    Obtiene la lista de todos los servidores VPN disponibles.
    
    Returns:
        Lista de servidores disponibles
    """
    # En una implementación real, esta información vendría de una base de datos
    # o de llamadas a servicios externos
    return settings.VPN_SERVERS

@router.get("/{server_id}", response_model=Server)
async def get_server(server_id: str):
    """
    Obtiene información detallada de un servidor específico.
    
    Args:
        server_id: ID único del servidor
        
    Returns:
        Información detallada del servidor
        
    Raises:
        HTTPException: Si el servidor no existe
    """
    for server in settings.VPN_SERVERS:
        if server["id"] == server_id:
            return server
    
    raise HTTPException(status_code=404, detail=f"Servidor con ID {server_id} no encontrado")
