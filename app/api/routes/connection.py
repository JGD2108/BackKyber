"""
Rutas de la API para gestión de conexiones VPN.

Este módulo implementa los endpoints para conectar/desconectar
la VPN y obtener su estado actual.
"""
import logging
import os
import traceback
import asyncio
import random
import uuid
from fastapi import APIRouter, HTTPException, Depends, Request
from typing import Dict, Any
from opencensus.ext.azure.metrics_exporter import AzureMetricsExporter

from app.models.schemas import ConnectionRequest, ConnectionResponse, VpnStatus
from app.network.vpn_client import vpn_client
from app.core.config import settings

# Set up logger properly
logger = logging.getLogger("kyber-vpn")

# Initialize Azure Application Insights
if os.environ.get('APPINSIGHTS_INSTRUMENTATIONKEY'):
    try:
        from opencensus.ext.azure.log_exporter import AzureLogHandler
        from opencensus.trace.samplers import AlwaysOnSampler
        from opencensus.trace.tracer import Tracer

        # Add Azure handler to logger
        azure_handler = AzureLogHandler(
            connection_string=f"InstrumentationKey={os.environ.get('APPINSIGHTS_INSTRUMENTATIONKEY')}"
        )
        logger.addHandler(azure_handler)
        
        # Configure Azure Metrics exporter
        metrics_exporter = AzureMetricsExporter(
            connection_string=f"InstrumentationKey={os.environ.get('APPINSIGHTS_INSTRUMENTATIONKEY')}"

        )
        logger.info("Azure Application Insights configured successfully")
    except ImportError:
        logger.warning("Azure Application Insights packages not fully installed")
    except Exception as e:
        logger.warning(f"Failed to initialize Azure monitoring: {str(e)}")

router = APIRouter()

@router.post("/connect")
async def connect_to_vpn(request: ConnectionRequest, req: Request = None):
    # Generate Azure correlation ID
    correlation_id = str(uuid.uuid4())
    client_ip = req.client.host if req else "unknown"
    logger.info(f"[{correlation_id}] VPN connection request from {client_ip} for server: {request.serverId}")
    
    try:
        # Verify settings is properly loaded
        if not hasattr(settings, 'VPN_SERVERS'):
            logger.error(f"[{correlation_id}] Configuration error: VPN_SERVERS not defined in settings")
            raise HTTPException(status_code=500, 
                             detail="Error de configuración del servidor VPN")
        
        server = next((s for s in settings.VPN_SERVERS if s["id"] == request.serverId), None)
        if not server:
            logger.error(f"[{correlation_id}] Servidor no encontrado: {request.serverId}")
            raise HTTPException(status_code=404, detail="Servidor no encontrado")
        
        logger.info(f"[{correlation_id}] Conectando a {server['ip']}:{server['port']}")
        
        # Azure-recommended retry pattern with circuit breaker
        max_retries = 3
        retry_count = 0
        backoff_factor = 2
        success = False
        
        while retry_count < max_retries and not success:
            try:
                # Add timeout for Azure environment - prevents hanging connections
                result = await asyncio.wait_for(
                    vpn_client.connect(server["ip"], server["port"]),
                    timeout=15.0  # Azure-appropriate timeout
                )
                success = True
            except asyncio.TimeoutError:
                retry_count += 1
                if retry_count >= max_retries:
                    logger.error(f"[{correlation_id}] Timeout al conectar a VPN después de {max_retries} intentos")
                    # Log to Azure metrics
                    if 'metrics_exporter' in locals():
                        try:
                            metrics_exporter.add_metrics({"VPN Connection Timeouts": 1})
                        except Exception:
                            pass
                    raise HTTPException(status_code=504, 
                                      detail="Timeout al conectar a VPN")
                
                # Azure recommended exponential backoff with jitter
                backoff = (backoff_factor ** retry_count) + (random.random() * 0.5)
                logger.warning(f"[{correlation_id}] Reintento {retry_count}/{max_retries} en {backoff:.2f}s")
                await asyncio.sleep(backoff)
            except Exception as e:
                retry_count += 1
                if retry_count >= max_retries:
                    logger.error(f"[{correlation_id}] Error en conexión VPN: {str(e)}", exc_info=True)
                    raise HTTPException(status_code=500, 
                                      detail=f"Error interno al conectar: {str(e)}")
                
                # Azure recommended exponential backoff with jitter
                backoff = (backoff_factor ** retry_count) + (random.random() * 0.5)
                logger.warning(f"[{correlation_id}] Reintento {retry_count}/{max_retries} en {backoff:.2f}s")
                await asyncio.sleep(backoff)
        
        # Log to Azure metrics
        if os.environ.get('APPINSIGHTS_INSTRUMENTATIONKEY') and 'metrics_exporter' in locals():
            try:
                metrics_exporter.add_metrics({
                    "VPN Connection Attempts": 1,
                    "VPN Connection Success": 1 if result["success"] else 0
                })
            except Exception as e:
                logger.warning(f"[{correlation_id}] Error al enviar métricas a Azure: {str(e)}")
        
        if not result["success"]:
            logger.error(f"[{correlation_id}] Conexión fallida: {result['message']}")
        else:
            logger.info(f"[{correlation_id}] Conexión exitosa. IP VPN: {result.get('vpnIp', 'unknown')}")
        
        return ConnectionResponse(**result)
    except HTTPException:
        raise
    except Exception as e:
        error_details = str(e)
        logger.error(f"[{correlation_id}] Error en conexión VPN: {error_details}", exc_info=True)
        
        # Track exception in Azure Application Insights
        if os.environ.get('APPINSIGHTS_INSTRUMENTATIONKEY'):
            try:
                from applicationinsights import TelemetryClient
                tc = TelemetryClient(os.environ.get('APPINSIGHTS_INSTRUMENTATIONKEY'))
                tc.track_exception()
            except ImportError:
                pass
        
        raise HTTPException(status_code=500, detail=f"Error interno al conectar: {error_details}")

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

# Add Azure-specific retries and monitoring in your VPN client
async def connect(self, ip, port):
    # Track connection attempts in Azure
    if os.environ.get("APPINSIGHTS_INSTRUMENTATIONKEY"):
        exporter = AzureMetricsExporter(
            connection_string=f"InstrumentationKey={os.environ.get('APPINSIGHTS_INSTRUMENTATIONKEY')}"
