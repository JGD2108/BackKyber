"""
Configuración de la aplicación Kyber VPN.

Este módulo define la configuración global utilizada en toda la aplicación,
incluyendo parámetros para la VPN, seguridad y red.
"""
import os
from typing import List, Union, Optional, Dict, Any
from pydantic import BaseSettings, AnyHttpUrl, validator
from enum import Enum
# Assuming ServerStatus is an Enum, you need to define or import it.
# For example, if it's in your models:
from app.models.schemas import ServerStatus # Or wherever ServerStatus is defined

class Settings(BaseSettings):
    """Configuración global de la aplicación."""
    
    # Configuración general
    PROJECT_NAME: str = "Kyber VPN"
    API_PREFIX: str = "/api"
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"
    
    # Configuración de seguridad
    SECRET_KEY: str = os.getenv("SECRET_KEY", "insecure_default_key_please_change_in_production")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8  # 8 days
    ALGORITHM: str = "HS256"
    
    # Configuración CORS
    CORS_ORIGINS: List[Union[str, AnyHttpUrl]] = [
        "https://20.83.144.149",
        "https://frontkyber.vercel.app" # Added your frontend URL
    ]
    
    # Configuración de red para VPN
    VPN_SUBNET: str = os.getenv("VPN_SUBNET", "10.8.0.0/24")
    VPN_SERVER_IP: str = os.getenv("VPN_SERVER_IP", "10.8.0.1") # This is likely the VPN's internal IP
    TUN_NAME: str = os.getenv("TUN_NAME", "tun0")
    
    # Configuración de criptografía
    KYBER_PARAMETER: str = os.getenv("KYBER_PARAMETER", "kyber768")
    
    # These should be actual values or fetched from env
    SERVER_HOST: str = os.getenv("SERVER_HOST", "20.83.144.149") # Public IP of your server
    VPN_PORT: int = int(os.getenv("VPN_PORT", "1194")) # Actual VPN listening port

    # Servidores VPN predefinidos
    # Option 1: Define directly if values are static or from env at load time
    VPN_SERVERS: List[Dict[str, Any]] = [] # Initialize and populate later if dependent on instance

    # Azure-specific settings
    BASE_URL: str = "https://20.83.144.149"

    def __init__(self, **values: Any):
        super().__init__(**values)
        # Option 2: Populate VPN_SERVERS here if they depend on other instance attributes
        if not self.VPN_SERVERS: # Populate only if not already set (e.g., by environment)
            self.VPN_SERVERS = [
                {
                    "id": "kyber-vpn-main",
                    "name": "Servidor Kyber VPN Principal",
                    "location": "Servidor Azure",
                    "ip": self.SERVER_HOST, # Use self.SERVER_HOST
                    "port": self.VPN_PORT,    # Use self.VPN_PORT
                    "status": ServerStatus.ONLINE.value if isinstance(ServerStatus.ONLINE, Enum) else ServerStatus.ONLINE, # Use .value if it's an Enum
                    "latency": 0,
                }
            ]

    @validator("CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()

# ... (ensure vpn_client and other parts of your app use this 'settings' instance)

