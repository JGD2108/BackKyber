"""
Configuración de la aplicación Kyber VPN con integración para Azure.
"""
from typing import List, Union, Optional, Dict, Any
from pydantic import BaseSettings, AnyHttpUrl, validator
import os
import logging

logger = logging.getLogger("kyber-vpn")

class Settings(BaseSettings):
    # API Configuration
    API_V1_STR: str = "/api"
    PROJECT_NAME: str = "Kyber VPN"
    
    # Server Configuration
    SERVER_HOST: str = os.environ.get("SERVER_HOST", "127.0.0.1")
    SERVER_PORT: int = int(os.environ.get("SERVER_PORT", "8000"))
    VPN_PORT: int = int(os.environ.get("VPN_PORT", "5000"))
    BASE_URL: str = os.environ.get("BASE_URL", "https://20.83.144.149")
    
    # CORS Configuration
    CORS_ORIGINS: List[str] = []
    
    # VPN Server List
    VPN_SERVERS: List[Dict[str, Any]] = []

    def __init__(self, **values: Any):
        super().__init__(**values)
        # Populate VPN_SERVERS if not already set
        if not self.VPN_SERVERS:
            # Log for debugging
            logger.info(f"Populating VPN_SERVERS with SERVER_HOST={self.SERVER_HOST}, VPN_PORT={self.VPN_PORT}")
            
            self.VPN_SERVERS = [
                {
                    "id": "kyber-vpn-main",  # MUST match what the frontend is sending
                    "name": "Servidor Kyber VPN Principal",
                    "location": "Azure VM",
                    "ip": self.SERVER_HOST,
                    "port": self.VPN_PORT,
                    "status": "online",
                    "latency": 0,
                }
            ]
            # Enhanced logging for Azure diagnostics
            logger.info(f"VPN_SERVERS populated: {self.VPN_SERVERS}")

    @validator("CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

settings = Settings()

