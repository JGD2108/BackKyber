"""
Simulación de interfaces TUN/TAP para VPN con fines educativos.

Este módulo simula la funcionalidad para crear y gestionar interfaces
TUN/TAP para implementar una VPN, pero sin interactuar realmente con
el sistema operativo, lo que permite ejecutar el código sin permisos
de administrador.
"""
import asyncio
import logging
from typing import Callable, Optional, Dict, Any
import ipaddress
import random

# Configurar logger
logger = logging.getLogger(__name__)

class TunManager:
    """
    Simulador de interfaces TUN/TAP para VPN con fines educativos.
    
    Esta clase simula el comportamiento de interfaces TUN/TAP sin interactuar
    realmente con el sistema operativo. Es útil para fines educativos y de
    demostración sin necesidad de permisos de administrador.
    """
    
    def __init__(self, name: str = "tun0", mode: str = "tun", mtu: int = 1500):
        """
        Inicializa el simulador de interfaces TUN/TAP.
        
        Args:
            name: Nombre simulado de la interfaz (ej: "tun0")
            mode: Modo simulado de la interfaz ("tun" o "tap")
            mtu: Maximum Transmission Unit simulado
        """
        if mode not in ["tun", "tap"]:
            raise ValueError("El modo debe ser 'tun' o 'tap'")
        
        self.name = name
        self.mode = mode
        self.mtu = mtu
        self.interface = None  # Simulación de interfaz
        self.running = False
        self.packet_callback = None
        self.ip_address = None
        self.netmask = None
        
        logger.info(f"Simulador de interfaz {name} inicializado (modo: {mode}, MTU: {mtu})")
    
    async def create_interface(self, ip_address: str, netmask: str = "255.255.255.0") -> bool:
        """
        Simula la creación y configuración de una interfaz TUN/TAP.
        
        Args:
            ip_address: Dirección IP para la interfaz simulada
            netmask: Máscara de red simulada
            
        Returns:
            True indicando que la simulación de la interfaz se creó correctamente
        """
        # Validar la dirección IP
        try:
            ipaddress.IPv4Address(ip_address)
        except ValueError:
            logger.error(f"Dirección IP inválida: {ip_address}")
            raise ValueError(f"Dirección IP inválida: {ip_address}")
        
        # Almacenar la configuración
        self.ip_address = ip_address
        self.netmask = netmask
        
        # Crear un objeto de simulación simple
        self.interface = {
            "name": self.name,
            "ip": ip_address,
            "netmask": netmask,
            "mtu": self.mtu,
            "is_up": True
        }
        
        logger.info(f"Interfaz simulada {self.name} creada con IP {ip_address}/{netmask}")
        return True
    
    def set_packet_callback(self, callback: Callable):
        """
        Establece la función de callback para procesar paquetes simulados.
        
        Args:
            callback: Función que será llamada cuando se 'reciban' paquetes simulados
        """
        self.packet_callback = callback
        logger.debug(f"Callback establecido para la interfaz simulada {self.name}")
    
    async def start(self):
        """
        Simula el inicio del procesamiento de paquetes en la interfaz TUN/TAP.
        
        En una implementación real, esto iniciaría un bucle para leer paquetes
        de la interfaz. En esta simulación, generamos paquetes aleatorios para
        mostrar el concepto.
        """
        if not self.interface:
            raise RuntimeError("La interfaz TUN simulada no ha sido creada")
        
        if not self.packet_callback:
            raise RuntimeError("No se ha definido un callback para procesar paquetes simulados")
        
        self.running = True
        logger.info(f"Iniciando simulación de procesamiento de paquetes en interfaz {self.name}")
        
        try:
            # Bucle principal para simular procesamiento de paquetes
            while self.running:
                # Simular un pequeño retraso
                await asyncio.sleep(random.uniform(0.5, 2.0))
                
                if not self.running:
                    break
                
                # Generar un paquete simulado aleatorio (solo bytes aleatorios)
                packet_size = random.randint(64, min(1400, self.mtu))
                packet = bytes([random.randint(0, 255) for _ in range(packet_size)])
                
                # Procesar el paquete simulado
                if self.packet_callback:
                    try:
                        await self.packet_callback(packet)
                    except Exception as e:
                        logger.error(f"Error en callback al procesar paquete simulado: {str(e)}")
        except asyncio.CancelledError:
            logger.info(f"Simulación de procesamiento de paquetes cancelada para {self.name}")
            self.running = False
        except Exception as e:
            logger.error(f"Error en la simulación de procesamiento: {str(e)}")
            self.running = False
            raise
    
    async def send_packet(self, packet: bytes):
        """
        Simula el envío de un paquete a través de la interfaz TUN/TAP.
        
        Args:
            packet: Datos del paquete simulado a 'enviar'
        """
        if not self.interface:
            raise RuntimeError("La interfaz TUN simulada no ha sido creada")
        
        if not self.interface["is_up"]:
            logger.warning(f"Intento de enviar paquete por interfaz {self.name} que está caída")
            return
        
        # Simular el envío (solo registramos información)
        logger.debug(f"Paquete simulado enviado por {self.name}: {len(packet)} bytes")
    
    async def stop(self):
        """
        Detiene la simulación del procesamiento de paquetes.
        """
        self.running = False
        
        if self.interface:
            # Simular el apagado de la interfaz
            self.interface["is_up"] = False
            logger.info(f"Interfaz simulada {self.name} apagada")