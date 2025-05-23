"""
Punto de entrada principal para la API de Kyber VPN.

Este módulo inicializa la aplicación FastAPI y registra todas las rutas
para la gestión de la VPN educativa resistente a ataques cuánticos.
"""
# Standard library imports
import asyncio
import json
import logging
import os
import traceback

# Third-party imports
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.responses import Response
from starlette.exceptions import HTTPException as StarletteHTTPException

# Local application imports
from app.core.config import settings
from app.api.routes.servers import router as servers_router
from app.api.routes.connection import router as connection_router
from app.api.routes.education import router as education_router
from app.api.routes.chat import router as chat_router
from app.network.vpn import vpn_server as global_vpn_server

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("kyber-vpn")

# Crear aplicación FastAPI
app = FastAPI(
    title="Kyber VPN API",
    description="API para VPN educativa resistente a ataques cuánticos usando CRYSTALS-Kyber",
    version="0.1.0",
)

# Registrar rutas
app.include_router(servers_router, prefix="/api/servers", tags=["servers"])
app.include_router(connection_router, prefix="/api", tags=["connection"])
app.include_router(education_router, prefix="/api/education", tags=["education"])
app.include_router(chat_router, prefix="/api/chat", tags=["chat"])  # Nueva ruta

@app.get("/")
async def root():
    """Endpoint raíz que proporciona información básica sobre la API."""
    return {
        "name": "Kyber VPN API",
        "description": "API para VPN educativa resistente a ataques cuánticos",
        "docs_url": "/docs",
        "version": "0.1.0"
    }

# Modify your health check endpoint

@app.get("/api/health")
async def health_check():
    """Endpoint for health verification with CORS headers."""
    import platform
    import psutil
    import datetime
    
    response = {
        "status": "ok",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "version": "0.1.0",
        "system": {
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent
        }
    }
    
    return response

@app.get("/api/status")
async def global_status():
    """
    Endpoint de estado global accesible sin autenticación.
    Proporciona información básica sobre el estado del servicio e indica
    si el sistema tiene los privilegios necesarios para una VPN real.
    """
    import datetime
    import platform
    import psutil
    import time
    import os
    
    # Obtener información básica del sistema
    cpu = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    
    # Calcular tiempo desde el inicio
    start_time = getattr(app.state, "start_time", None)
    if not start_time:
        app.state.start_time = time.time()
        start_time = app.state.start_time
    
    uptime = time.time() - start_time
    fully_initialized = uptime > 5  # Considerar inicializado después de 5 segundos
    
    # Verificar si tenemos privilegios de administrador
    is_admin = False
    try:
        if platform.system().lower() == "windows":
            # En Windows, verificar membresía en grupo de administradores
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            # En Unix/Linux, verificar si el UID es 0 (root)
            is_admin = os.geteuid() == 0
    except:
        pass
    
    # Verificar si podemos crear interfaces TUN/TAP
    can_create_tun = False
    try:
        if platform.system().lower() == "linux":
            # Verificar si existe /dev/net/tun y tenemos permisos
            tun_exists = os.path.exists("/dev/net/tun")
            tun_access = os.access("/dev/net/tun", os.R_OK | os.W_OK)
            can_create_tun = tun_exists and tun_access and is_admin
        elif platform.system().lower() == "windows":
            # En Windows necesitamos tener el driver TAP instalado
            # Esto es una verificación básica, no 100% precisa
            import subprocess
            try:
                # Buscar adaptadores TAP de OpenVPN
                proc = subprocess.run(
                    "netsh interface show interface", 
                    capture_output=True, 
                    text=True, 
                    shell=True
                )
                can_create_tun = "TAP-Windows" in proc.stdout and is_admin
            except:
                can_create_tun = False
    except:
        pass
    
    # Determinar si estamos en un entorno cloud que no permite VPN real
    is_cloud_env = False
    try:
        # Verificar variables de entorno comunes en proveedores cloud
        is_cloud_env = bool(os.environ.get("RENDER") or 
                           os.environ.get("VERCEL") or 
                           os.environ.get("HEROKU_APP_ID"))
    except:
        pass
    
    # Determinar el modo de operación
    if is_admin and can_create_tun and not is_cloud_env:
        operation_mode = "vpn_capable"
        operation_message = "Sistema capaz de operar como VPN real"
    else:
        operation_mode = "simulation"
        if is_cloud_env:
            operation_message = "Ejecutando en modo simulación (entorno cloud detectado)"
        elif not is_admin:
            operation_message = "Ejecutando en modo simulación (se requieren privilegios de administrador)"
        elif not can_create_tun:
            operation_message = "Ejecutando en modo simulación (no se puede acceder a interfaces TUN/TAP)"
        else:
            operation_message = "Ejecutando en modo simulación"
    
    return {
        "connected": False,
        "service_status": "ready" if fully_initialized else "initializing",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "uptime": uptime,
        "operation_mode": operation_mode,
        "system": {
            "cpu_percent": cpu,
            "memory_percent": memory.percent,
            "python_version": platform.python_version(),
            "os": platform.system(),
            "admin_privileges": is_admin,
            "tun_tap_capability": can_create_tun,
            "cloud_environment": is_cloud_env
        },
        "message": operation_message
    }

@app.on_event("startup")
async def startup_event():
    """Iniciar proceso en segundo plano para mantener la instancia activa y iniciar VPN server."""
    # Existing anti-sleep task
    logger.info("Iniciando servicio anti-sleep.")
    async def keep_alive():
        """Tarea en segundo plano para realizar un self-ping periódico."""
        import asyncio
        import random
        import aiohttp
        import ssl # Import ssl module
        
        # URL del servicio (a sí mismo)
        # Ensure settings.BASE_URL is correctly set to your Azure VM's HTTPS URL
        base_url = settings.BASE_URL # Example: "https://20.83.144.149"
        if not base_url:
            logger.warning("settings.BASE_URL is not set for anti-sleep task. Skipping self-ping.")
            return

        service_url = f"{base_url}/api/health"
        
        # Create an SSL context that does not verify certificates
        # WARNING: This disables SSL certificate verification for this specific request.
        # This is generally acceptable for a self-ping to a service you control
        # if you are using a self-signed certificate.
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        logger.info(f"Anti-sleep task will ping: {service_url}")

        while True:
            try:
                # Esperar entre 10-14 minutos
                await asyncio.sleep(600 + random.randint(0, 240))
                
                async with aiohttp.ClientSession() as session:
                    # Hacer ping al servicio, using the custom ssl_context
                    async with session.get(service_url, ssl=ssl_context) as response:
                        if response.status == 200:
                            logger.debug(f"Anti-sleep ping to {service_url} successful: {response.status}")
                        else:
                            logger.warning(f"Anti-sleep ping to {service_url} fallido: {response.status}")
            except aiohttp.ClientConnectorError as e:
                logger.error(f"Error de conexión en anti-sleep a {service_url}: {str(e)}")
                await asyncio.sleep(300) # Esperar 5 minutos en caso de error de conexión
            except Exception as e:
                logger.error(f"Error general en anti-sleep ({service_url}): {str(e)}", exc_info=True)
                await asyncio.sleep(300)  # Esperar 5 minutos en caso de error
    
    # Iniciar tarea en segundo plano
    import asyncio
    import platform
    import time
    asyncio.create_task(keep_alive())

    # Start the VPN Server with enhanced privilege checking
    logger.info("Checking system capabilities for VPN server...")
    try:
        # Check if we're in cloud environment
        is_cloud_env = bool(os.environ.get("RENDER") or
                           os.environ.get("VERCEL") or
                           os.environ.get("HEROKU_APP_ID"))

        # Check for admin privileges - crucial for TUN interface creation
        is_admin = False
        try:
            if platform.system().lower() == "windows":
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                # In Unix/Linux, check if we're root
                is_admin = os.geteuid() == 0
        except Exception as e:
            logger.warning(f"Failed to check admin privileges: {str(e)}")
            is_admin = False

        # Check TUN/TAP capability
        can_create_tun = False
        try:
            if platform.system().lower() == "linux":
                tun_exists = os.path.exists("/dev/net/tun")
                tun_access = os.access("/dev/net/tun", os.R_OK | os.W_OK)
                can_create_tun = tun_exists and tun_access and is_admin
            elif platform.system().lower() == "windows":
                # Windows TAP adapter check...
                import subprocess
                try:
                    proc = subprocess.run(
                        "netsh interface show interface", 
                        capture_output=True, 
                        text=True, 
                        shell=True
                    )
                    can_create_tun = "TAP-Windows" in proc.stdout and is_admin
                except Exception:
                    can_create_tun = False
        except Exception as e:
            logger.warning(f"Failed to check TUN/TAP capability: {str(e)}")
            can_create_tun = False

        # Only attempt to start real VPN if we have required privileges
        if is_admin and can_create_tun and not is_cloud_env:
            logger.info("System has required privileges for VPN functionality. Starting VPN server...")
            # Log server attributes before starting
            logger.info(f"VPN server object type: {type(global_vpn_server)}")
            logger.info(f"VPN server port: {global_vpn_server.port}")
            logger.info(f"VPN server subnet: {global_vpn_server.subnet}")
            
            # The VPNServer.start() method is long-running
            vpn_task = asyncio.create_task(global_vpn_server.start())
            
            # Add a callback to handle task exceptions
            def handle_vpn_task_exception(task):
                try:
                    task.result()
                except PermissionError as e:
                    logger.error(f"VPN server failed due to insufficient permissions: {str(e)}")
                    logger.info("To run with full VPN functionality, restart the service with root privileges: sudo systemctl restart kyber-api")
                except Exception as e:
                    logger.error(f"VPN server task failed with: {str(e)}", exc_info=True)
            
            vpn_task.add_done_callback(handle_vpn_task_exception)
            logger.info("Kyber VPN server startup task created.")
        else:
            # Provide detailed reason why we're in simulation mode
            if is_cloud_env:
                reason = "cloud environment detected"
            elif not is_admin:
                reason = "insufficient privileges"
                logger.info("To run with full VPN functionality, restart the service with: sudo systemctl restart kyber-api")
            elif not can_create_tun:
                reason = "missing TUN/TAP capability"
            else:
                reason = "unknown restriction"
                
            logger.warning(f"Kyber VPN operating in SIMULATION mode ({reason})")
    except Exception as e:
        logger.error(f"Error during VPN server startup checks: {e}", exc_info=True)

@app.on_event("shutdown")
async def shutdown_event():
    """Detener el servidor VPN al cerrar la aplicación."""
    logger.info("Attempting to stop Kyber VPN server...")
    try:
        await global_vpn_server.stop()
        logger.info("Kyber VPN server stopped.")
    except AttributeError as e:
        logger.error(f"Failed to stop VPN server: Method not found on vpn_server instance. Details: {e}", exc_info=True)
    except Exception as e:
        logger.error(f"Error during Kyber VPN server shutdown: {e}", exc_info=True)

# Add these exception handlers before your app routes
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    """Enhanced HTTP exception handler with Azure-friendly logging"""
    logger.error(f"HTTP Exception: {exc.status_code} - {exc.detail}")
    return Response(
        status_code=exc.status_code,
        content=json.dumps({"error": exc.detail, "status_code": exc.status_code}),
        media_type="application/json"
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    """Detailed validation error handler with Azure-friendly logging"""
    error_detail = str(exc)
    logger.error(f"Validation Error: {error_detail}")
    
    return Response(
        status_code=422,
        content=json.dumps({
            "error": "Validation Error",
            "detail": error_detail,
            "status_code": 422
        }),
        media_type="application/json"
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    """Catch-all exception handler with Azure-friendly error format"""
    error_detail = str(exc)
    trace = traceback.format_exc()
    logger.error(f"Unhandled Exception: {error_detail}\n{trace}")
    
    return Response(
        status_code=500,
        content=json.dumps({
            "error": "Internal Server Error",
            "detail": error_detail if app.debug else "An unexpected error occurred",
            "status_code": 500
        }),
        media_type="application/json"
    )

