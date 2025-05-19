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
import aiohttp
from fastapi import APIRouter, HTTPException, Depends, Request, Response
from typing import Dict, Any, Optional

# Azure SDK imports for best practices
from azure.monitor.opentelemetry import configure_azure_monitor
from opencensus.ext.azure.metrics_exporter import AzureMetricsExporter
from opencensus.ext.azure.log_exporter import AzureLogHandler
from azure.identity import DefaultAzureCredential

from app.models.schemas import ConnectionRequest, ConnectionResponse, VpnStatus
from app.network.vpn_client import vpn_client
from app.core.config import settings

# Set up logger properly
logger = logging.getLogger("kyber-vpn")

# Initialize Azure Application Insights with modern connection string format
if os.environ.get('APPLICATIONINSIGHTS_CONNECTION_STRING'):
    try:
        # Modern Azure Monitor approach (recommended)
        configure_azure_monitor(
            connection_string=os.environ.get('APPLICATIONINSIGHTS_CONNECTION_STRING')
        )
        logger.info("Azure Monitor OpenTelemetry configured successfully")
    except ImportError:
        logger.warning("Azure Monitor OpenTelemetry not installed, using legacy approach")
        # Fall back to legacy approach
        if os.environ.get('APPINSIGHTS_INSTRUMENTATIONKEY'):
            try:
                # Convert instrumentation key to connection string format
                connection_string = f"InstrumentationKey={os.environ.get('APPINSIGHTS_INSTRUMENTATIONKEY')}"
                
                # Add Azure handler to logger
                azure_handler = AzureLogHandler(connection_string=connection_string)
                logger.addHandler(azure_handler)
                
                # Configure Azure Metrics exporter
                metrics_exporter = AzureMetricsExporter(connection_string=connection_string)
                logger.info("Azure Application Insights configured successfully with legacy approach")
            except Exception as e:
                logger.warning(f"Failed to initialize Azure monitoring: {str(e)}")

# Use managed identity for secure access to Azure services
credential = DefaultAzureCredential()

router = APIRouter()

# Add a dedicated health check endpoint with CORS headers
@router.get("/health")
async def health_check(response: Response):
    """
    Azure-optimized health check endpoint with CORS headers and enhanced Azure monitoring
    """
    # Add CORS headers for Azure Front Door and Application Gateway compatibility
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Azure-FDID, X-Azure-Ref"
    
    # Log health check with Azure-specific dimensions
    if os.environ.get('APPINSIGHTS_INSTRUMENTATIONKEY') and 'metrics_exporter' in globals():
        try:
            metrics_exporter.add_metrics({
                "Health Check Requests": 1
            }, 
            {'Region': os.environ.get('REGION_NAME', 'unknown')})
        except Exception as e:
            logger.warning(f"Error sending metrics to Azure: {str(e)}")
    
    # Return enhanced health check response
    return {
        "status": "ok", 
        "environment": "azure",
        "version": getattr(settings, "API_VERSION", "1.0.0"),
        "timestamp": asyncio.get_event_loop().time()
    }

@router.post("/connect")
async def connect_to_vpn(request: ConnectionRequest, req: Request = None):
    # Generate Azure-friendly correlation ID
    correlation_id = f"kyber-{uuid.uuid4()}"
    client_ip = req.client.host if req else "unknown"
    
    # Structure logs for Azure Log Analytics queries
    logger.info(f"VPN connection request initiated", extra={
        'custom_dimensions': {
            'correlation_id': correlation_id,
            'client_ip': client_ip, 
            'server_id': request.serverId,
            'operation': 'connect'
        }
    })
    
    try:
        # Verify settings is properly loaded
        if not hasattr(settings, 'VPN_SERVERS'):
            logger.error(f"Configuration error: VPN_SERVERS not defined in settings", extra={
                'custom_dimensions': {
                    'correlation_id': correlation_id,
                    'error_type': 'config_error'
                }
            })
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
                    if 'metrics_exporter' in globals():
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
        if os.environ.get('APPINSIGHTS_INSTRUMENTATIONKEY') and 'metrics_exporter' in globals():
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

# Python version of the health check client (replacing the JavaScript code)
async def azure_health_check(base_url: str, retry_attempts: int = 3) -> bool:
    """
    Azure-optimized health check with proper error handling and instrumentation
    """
    health_endpoint = '/api/health'
    cache_param = f"t={uuid.uuid4()}"
    request_id = f"health-{uuid.uuid4().hex[:8]}"
    
    # Track operation start in Azure using the recommended Azure Monitor API
    if os.environ.get('APPLICATIONINSIGHTS_CONNECTION_STRING'):
        try:
            # Use the modern Azure Monitor approach first if available
            from azure.monitor.opentelemetry import configure_azure_monitor
            from opentelemetry import trace
            from opentelemetry.trace import Status, StatusCode
            
            tracer = trace.get_tracer(__name__)
            with tracer.start_as_current_span("azure_health_check") as span:
                span.set_attribute("request_id", request_id)
                span.set_attribute("target_url", base_url)
        except ImportError:
            # Fall back to legacy approach
            if os.environ.get('APPINSIGHTS_INSTRUMENTATIONKEY') and 'metrics_exporter' in globals():
                try:
                    metrics_exporter.add_metrics(
                        {"Health Check Attempts": 1},
                        {
                            'operation': 'health_check',
                            'request_id': request_id,
                            'target': base_url
                        }
                    )
                except Exception as e:
                    logger.warning(f"Failed to log metrics to Azure: {str(e)}")
    
    async with aiohttp.ClientSession() as session:
        for attempt in range(1, retry_attempts + 1):
            try:
                # Configure timeout according to Azure recommendations
                timeout = aiohttp.ClientTimeout(
                    total=15,      # Total operation timeout
                    connect=5,     # Connection establishment timeout
                    sock_read=10   # Socket read timeout
                )
                
                # Add Azure-specific headers for distributed tracing
                headers = {
                    'X-Azure-Client': 'true',
                    'Cache-Control': 'no-cache',
                    'X-Request-ID': request_id,
                    'User-Agent': 'KyberVPN-Client/1.0',
                    # Add W3C trace context headers for Azure distributed tracing
                    'traceparent': f'00-{uuid.uuid4().hex}-{uuid.uuid4().hex[:16]}-01'
                }
                
                # Make the request with Azure-appropriate settings
                async with session.get(
                    f"{base_url}{health_endpoint}?{cache_param}",
                    headers=headers,
                    ssl=False,  # For development. Use proper cert validation in production
                    timeout=timeout
                ) as response:
                    # Log response in structured format for Azure Log Analytics
                    if response.status == 200:
                        logger.info('Azure VM connection successful', extra={
                            'custom_dimensions': {
                                'request_id': request_id,
                                'attempt': attempt,
                                'statusCode': response.status,
                                'service': 'vpn_health_check'
                            }
                        })
                        
                        # Track successful health check using recommended Azure pattern
                        if os.environ.get('APPLICATIONINSIGHTS_CONNECTION_STRING'):
                            try:
                                # Modern approach
                                if 'span' in locals():
                                    span.set_status(Status(StatusCode.OK))
                            except Exception:
                                pass
                        elif os.environ.get('APPINSIGHTS_INSTRUMENTATIONKEY') and 'metrics_exporter' in globals():
                            # Legacy approach
                            try:
                                metrics_exporter.add_metrics(
                                    {"Health Check Success": 1},
                                    {
                                        'result': 'success',
                                        'attempts': attempt,
                                        'operation': 'health_check'
                                    }
                                )
                            except Exception:
                                pass
                        
                        return True
                    else:
                        logger.warning(f"Health check received non-200 status: {response.status}", extra={
                            'custom_dimensions': {
                                'request_id': request_id,
                                'status_code': response.status,
                                'attempt': attempt,
                                'response_text': await response.text()
                            }
                        })
                    
            except (aiohttp.ClientError, asyncio.TimeoutError) as error:
                # Detailed error logging for Azure diagnostics
                error_type = type(error).__name__
                logger.warning(f"Health check attempt {attempt} failed: {error_type}", extra={
                    'custom_dimensions': {
                        'request_id': request_id,
                        'error': str(error),
                        'attempt': attempt,
                        'error_type': error_type,
                        'connection_url': f"{base_url}{health_endpoint}"
                    }
                })
                
                # Azure-recommended exponential backoff with jitter
                if attempt < retry_attempts:
                    # Cap maximum backoff at 30 seconds per Azure recommendations
                    backoff_time = min(30, (2 ** attempt) + (random.random() * 0.5))
                    logger.info(f"Retrying in {backoff_time:.2f} seconds", extra={
                        'custom_dimensions': {
                            'request_id': request_id,
                            'backoff_time': backoff_time,
                            'retry_attempt': attempt
                        }
                    })
                    await asyncio.sleep(backoff_time)
    
    # Track failed health check in Azure
    if os.environ.get('APPLICATIONINSIGHTS_CONNECTION_STRING'):
        try:
            # Modern approach
            if 'span' in locals():
                span.set_status(Status(StatusCode.ERROR))
                span.record_exception(Exception("Health check failed after all attempts"))
        except Exception:
            pass
    elif os.environ.get('APPINSIGHTS_INSTRUMENTATIONKEY') and 'metrics_exporter' in globals():
        # Legacy approach
        try:
            metrics_exporter.add_metrics(
                {"Health Check Failures": 1},
                {
                    'result': 'failure',
                    'attempts': retry_attempts,
                    'operation': 'health_check'
                }
            )
        except Exception:
            pass
            
    logger.error('All connection attempts to Azure VM failed', extra={
        'custom_dimensions': {
            'request_id': request_id,
            'total_attempts': retry_attempts,
            'base_url': base_url
        }
    })
    return False
