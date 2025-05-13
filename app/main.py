"""
Punto de entrada principal para la API de Kyber VPN.

Este módulo inicializa la aplicación FastAPI y registra todas las rutas
para la gestión de la VPN educativa resistente a ataques cuánticos.
"""
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware  # Descomentado para habilitar CORS

from app.core.config import settings
# Importar todos los routers
from app.api.routes.servers import router as servers_router
from app.api.routes.connection import router as connection_router
from app.api.routes.education import router as education_router
from app.api.routes.chat import router as chat_router  # Nueva importación

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

# Configurar CORS para permitir solicitudes desde el frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://frontkyber.vercel.app", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Type", "X-Requested-With", "Authorization"]
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
    """Iniciar proceso en segundo plano para mantener la instancia activa."""
    logger.info("Iniciando servicio anti-sleep para prevenir hibernación en Render.com")
    
    async def keep_alive():
        """Tarea en segundo plano para evitar que Render.com hiberne la instancia."""
        import asyncio
        import random
        import aiohttp
        
        # URL del servicio (a sí mismo)
        base_url = settings.BASE_URL or "https://backkyber.onrender.com"
        service_url = f"{base_url}/api/health"
        
        while True:
            try:
                # Esperar entre 10-14 minutos (menos que el tiempo de hibernación de 15 min)
                await asyncio.sleep(600 + random.randint(0, 240))
                
                async with aiohttp.ClientSession() as session:
                    # Hacer ping al servicio
                    async with session.get(service_url) as response:
                        if response.status == 200:
                            logger.debug("Anti-sleep ping exitoso")
                        else:
                            logger.warning(f"Anti-sleep ping fallido: {response.status}")
            except Exception as e:
                logger.error(f"Error en anti-sleep: {str(e)}")
                await asyncio.sleep(300)  # Esperar 5 minutos en caso de error
    
    # Iniciar tarea en segundo plano
    import asyncio
    asyncio.create_task(keep_alive())
