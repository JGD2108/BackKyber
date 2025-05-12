"""
Utilidades para operaciones de red.

Este módulo contiene funciones auxiliares relacionadas con operaciones de red,
como gestión de IPs, cálculos de subred, etc.
"""
import ipaddress
import socket
from typing import Optional, Dict, Any

def is_valid_ip(ip: str) -> bool:
    """
    Verifica si una dirección IP es válida.
    
    Args:
        ip: Dirección IP a verificar
        
    Returns:
        True si la IP es válida, False en caso contrario
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_ip_info(ip: str) -> Dict[str, Any]:
    """
    Obtiene información sobre una dirección IP.
    
    Args:
        ip: Dirección IP a analizar
        
    Returns:
        Diccionario con información sobre la IP
    """
    if not is_valid_ip(ip):
        return {"error": "IP inválida"}
    
    ip_obj = ipaddress.ip_address(ip)
    
    return {
        "ip": str(ip_obj),
        "version": ip_obj.version,
        "is_private": ip_obj.is_private,
        "is_global": ip_obj.is_global,
        "is_multicast": ip_obj.is_multicast,
        "is_loopback": ip_obj.is_loopback
    }

def get_public_ip() -> Optional[str]:
    """
    Intenta determinar la dirección IP pública del host.
    
    Returns:
        Dirección IP pública o None si no se puede determinar
    """
    try:
        # Existen varios servicios que pueden devolver la IP pública
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("ifconfig.me", 80))
            s.sendall(b"GET / HTTP/1.0\\r\\nHost: ifconfig.me\\r\\n\\r\\n")
            response = s.recv(4096)
        
        # Extraer la IP de la respuesta HTTP
        ip = response.decode().split("\\r\\n\\r\\n")[1].strip()
        return ip if is_valid_ip(ip) else None
    except Exception:
        return None

def parse_cidr(cidr: str) -> Dict[str, Any]:
    """
    Analiza una notación CIDR y devuelve información de la red.
    
    Args:
        cidr: Notación CIDR (ej: '192.168.1.0/24')
        
    Returns:
        Información sobre la red especificada
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return {
            "network_address": str(network.network_address),
            "broadcast_address": str(network.broadcast_address),
            "netmask": str(network.netmask),
            "prefixlen": network.prefixlen,
            "num_addresses": network.num_addresses,
            "hosts": [str(ip) for ip in list(network.hosts())[:5]] + ['...']  # Primeros 5 hosts
        }
    except ValueError:
        return {"error": "CIDR inválido"}
