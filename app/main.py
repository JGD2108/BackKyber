"""
Punto de entrada principal para la API de Kyber VPN.

Este módulo inicializa la aplicación FastAPI y registra todas las rutas
para la gestión de la VPN educativa resistente a ataques cuánticos.
"""
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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
    # Permitir cualquier origen en desarrollo
    allow_origins=["*"] if settings.DEBUG else [
        "http://localhost:3000", 
        "https://frontkyber.vercel.app",
        "https://backkyber.onrender.com"
        
    ],
    allow_credentials=False,  # Cambiar a False cuando allow_origins=["*"]
    allow_methods=["*"],
    allow_headers=["*"],
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

@app.get("/api/health")
async def health_check():
    """Endpoint mejorado para verificación de salud compatible con Azure."""
    import platform
    import psutil
    import datetime
    
    return {
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

@app.get("/api/status")
async def global_status():
    """
    Endpoint de estado global accesible sin autenticación.
    Proporciona información básica sobre el estado del servicio.
    """
    import datetime
    import platform
    import psutil
    import time
    
    # Obtener información básica del sistema
    cpu = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()
    
    return {
        "connected": False,  # Default state for unauthenticated access
        "service_status": "online",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "uptime": time.time() - psutil.boot_time(),
        "system": {
            "cpu_percent": cpu,
            "memory_percent": memory.percent,
            "python_version": platform.python_version(),
        },
        "message": "Servicio activo en Render.com"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=settings.DEBUG)
