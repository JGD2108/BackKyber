"""
Configuración de la aplicación Kyber VPN.

Este módulo define la configuración global utilizada en toda la aplicación,
incluyendo parámetros para la VPN, seguridad y red.
"""
import os
from typing import List, Union, Optional, Dict, Any  # <-- Agrega Dict y Any aquí

from pydantic import BaseSettings, AnyHttpUrl, validator

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
        "http://localhost:3000",  # Frontend React en desarrollo
        "http://localhost:8080",
        "https://c365-186-170-119-130.ngrok-free.app"  # Añade tu URL de Ngrok (sin /api)
    ]
    
    # Configuración de red para VPN
    VPN_SUBNET: str = os.getenv("VPN_SUBNET", "10.8.0.0/24")
    VPN_SERVER_IP: str = os.getenv("VPN_SERVER_IP", "10.8.0.1")
    TUN_NAME: str = os.getenv("TUN_NAME", "tun0")
    
    # Configuración de criptografía
    KYBER_PARAMETER: str = os.getenv("KYBER_PARAMETER", "kyber768")  # kyber512, kyber768, kyber1024
    
    # Servidores VPN predefinidos (para desarrollo/demo)
    # En producción, estos datos vendrían de una base de datos
    VPN_SERVERS: List[Dict[str, Any]] = [
        {
            "id": "server1",
            "name": "Servidor Principal",
            "location": "Madrid, España",
            "ip": "192.168.1.1",
            "port": 1194,
            "status": "online",
            "latency": 25
        },
        {
            "id": "server2",
            "name": "Servidor Respaldo",
            "location": "Barcelona, España",
            "ip": "192.168.1.2",
            "port": 1194,
            "status": "online",
            "latency": 35
        },
        {
            "id": "server3",
            "name": "Servidor Internacional",
            "location": "Frankfurt, Alemania",
            "ip": "192.168.1.3",
            "port": 1194,
            "status": "online",
            "latency": 50
        }
    ]
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Crear instancia global de configuración
settings = Settings()
