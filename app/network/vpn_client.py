"""
Implementación de un cliente VPN con resistencia post-cuántica.

Este módulo implementa un cliente VPN real utilizando interfaces TUN/TAP
y criptografía post-cuántica para proteger las conexiones.
"""
import asyncio
import logging
import ipaddress
import os
import time
import socket
import struct
import json
from typing import Dict, Any, Optional, Callable, List

from app.crypto.kyber import KyberManager
from app.crypto.symmetric import AESGCMCipher
from app.network.tun import TunDevice
from app.core.config import settings

# Configurar logger
logger = logging.getLogger(__name__)

class VPNClient:
    """
    Cliente VPN real con soporte para criptografía post-cuántica.
    
    Implementa un cliente VPN completo que establece una conexión segura
    con un servidor VPN utilizando Kyber para intercambio de claves y
    AES-GCM para cifrado de datos.
    """
    
    def __init__(self):
        """Inicializa el cliente VPN."""
        self.server_host = None
        self.server_port = None
        self.tun = None
        self.reader = None
        self.writer = None
        self.running = False
        self.cipher = None
        self.vpn_ip = None
        self.subnet = None
        self.connection_time = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        
        # Inicializar Kyber para intercambio de claves
        self.kyber = KyberManager(parameter_set=settings.KYBER_PARAMETER)
        
        # Callbacks
        self.status_callback = None
        
        logger.info("Cliente VPN inicializado")
    
    def set_status_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """
        Establece un callback para actualizaciones de estado.
        
        Args:
            callback: Función que será llamada con actualizaciones de estado
        """
        self.status_callback = callback
    
    async def connect(self, server_host: str, server_port: int) -> Dict[str, Any]:
        """
        Establece una conexión VPN con el servidor especificado.
        
        Args:
            server_host: Dirección del servidor VPN
            server_port: Puerto del servidor VPN
            
        Returns:
            Resultado de la conexión
        """
        if self.running:
            return {"success": False, "message": "La VPN ya está conectada"}
        
        self.server_host = server_host
        self.server_port = server_port
        
        logger.info(f"Iniciando conexión a {server_host}:{server_port}...")
        self._update_status("connecting")
        
        try:
            # Set a connection timeout of 5 seconds
            logger.info(f"Conectando al servidor VPN: {server_host}:{server_port}...")
            connect_task = asyncio.open_connection(server_host, server_port)
            reader, writer = await asyncio.wait_for(connect_task, timeout=5.0)
            logger.info("Conexión TCP establecida correctamente")
            
            self.reader = reader
            self.writer = writer
            
            # Generar par de claves Kyber
            logger.info("Generando par de claves Kyber...")
            keypair = self.kyber.generate_keypair()
            
            # Enviar clave pública al servidor
            public_key = keypair["public_key"].encode() if isinstance(keypair["public_key"], str) else keypair["public_key"]
            await self._send_data(public_key)
            
            # Recibir ciphertext del servidor
            ciphertext = await self._receive_data()
            
            # Desencapsular la clave compartida
            shared_key = self.kyber.decapsulate(ciphertext, keypair["secret_key"].encode() if isinstance(keypair["secret_key"], str) else keypair["secret_key"])
            
            # Inicializar cifrado AES con la clave compartida
            self.cipher = AESGCMCipher(key=shared_key)
            
            # Recibir configuración cifrada del servidor
            encrypted_config = await self._receive_data()
            
            # Separar nonce y ciphertext
            nonce = encrypted_config[:12]
            config_ciphertext = encrypted_config[12:]
            
            # Descifrar configuración
            config_data = self.cipher.decrypt(nonce, config_ciphertext)
            config = json.loads(config_data.decode())
            
            # Extraer información de configuración
            self.vpn_ip = config["vpn_ip"]
            self.subnet = config["subnet"]
            routes = config.get("routes", [])
            
            # Crear y configurar interfaz TUN
            logger.info(f"Creando interfaz TUN con IP {self.vpn_ip}...")
            self.tun = TunDevice(name="tun0", mode="tun")
            
            # Convertir subnet a netmask
            network = ipaddress.IPv4Network(self.subnet)
            netmask = str(network.netmask)
            
            # Crear interfaz con IP asignada
            await self.tun.create_interface(self.vpn_ip, netmask)
            
            # Configurar rutas
            for route in routes:
                await self._add_route(route)
            
            # Configurar callback para procesar paquetes
            self.tun.set_packet_callback(self._process_tun_packet)
            
            # Iniciar procesamiento de paquetes TUN
            self.running = True
            self.connection_time = time.time()
            
            # Iniciar tareas en segundo plano
            asyncio.create_task(self.tun.start())
            asyncio.create_task(self._process_network_data())
            
            # Notificar conexión exitosa
            self._update_status("connected")
            
            logger.info(f"Conexión VPN establecida, IP: {self.vpn_ip}")
            return {
                "success": True,
                "message": "Conexión VPN establecida",
                "vpnIp": self.vpn_ip
            }
        
        except Exception as e:
            logger.error(f"Error al conectar VPN: {str(e)}")
            await self.disconnect()
            return {
                "success": False,
                "message": f"Error de conexión: {str(e)}"
            }
    
    async def disconnect(self) -> Dict[str, Any]:
        """
        Finaliza la conexión VPN.
        
        Returns:
            Resultado de la desconexión
        """
        self._update_status("disconnecting")
        
        # Marcar como no ejecutándose para que las tareas se detengan
        self.running = False
        
        try:
            # Cerrar interfaz TUN
            if self.tun:
                await self.tun.stop()
                self.tun = None
            
            # Cerrar conexión con el servidor
            if self.writer:
                self.writer.close()
                try:
                    await self.writer.wait_closed()
                except:
                    pass
                self.writer = None
                self.reader = None
            
            # Restablecer variables
            self.vpn_ip = None
            self.subnet = None
            self.cipher = None
            self.bytes_sent = 0
            self.bytes_received = 0
            self.connection_time = 0
            
            # Notificar desconexión
            self._update_status("disconnected")
            
            logger.info("Desconexión VPN completada")
            return {
                "success": True,
                "message": "Desconexión exitosa"
            }
        
        except Exception as e:
            logger.error(f"Error al desconectar VPN: {str(e)}")
            
            # Asegurar actualización de estado incluso en error
            self._update_status("error")
            
            return {
                "success": False,
                "message": f"Error al desconectar: {str(e)}"
            }
    
    async def _process_network_data(self):
        """
        Procesa los datos recibidos del servidor VPN.
        """
        try:
            while self.running and self.reader:
                try:
                    # Leer tamaño del paquete
                    size_data = await self.reader.readexactly(4)
                    packet_size = struct.unpack("!I", size_data)[0]
                    
                    # Leer paquete cifrado
                    encrypted_data = await self.reader.readexactly(packet_size)
                    
                    # Separar nonce y ciphertext
                    nonce = encrypted_data[:12]
                    ciphertext = encrypted_data[12:]
                    
                    # Descifrar paquete
                    packet = self.cipher.decrypt(nonce, ciphertext)
                    
                    # Enviar a la interfaz TUN
                    await self.tun.send_packet(packet)
                    
                    # Actualizar estadísticas
                    self.bytes_received += len(packet)
                    self._update_status("stats_update")
                    
                except asyncio.IncompleteReadError:
                    # Conexión cerrada por el servidor
                    logger.warning("Conexión cerrada por el servidor")
                    break
                except Exception as e:
                    if self.running:
                        logger.error(f"Error procesando datos de red: {str(e)}")
                    else:
                        break
        
        except asyncio.CancelledError:
            # Cancelación normal
            pass
        except Exception as e:
            logger.error(f"Error en bucle de procesamiento de red: {str(e)}")
        finally:
            if self.running:
                # Si llegamos aquí con running=True, es una desconexión inesperada
                logger.warning("Desconexión inesperada del servidor")
                asyncio.create_task(self.disconnect())
    
    async def _process_tun_packet(self, packet: bytes):
        """
        Procesa un paquete recibido de la interfaz TUN.
        
        Args:
            packet: Datos del paquete IP
        """
        if not self.running or not self.writer or not self.cipher:
            return
        
        try:
            # Cifrar el paquete
            encrypted = self.cipher.encrypt(packet)
            
            # Enviar tamaño del paquete cifrado
            total_size = len(encrypted["nonce"]) + len(encrypted["ciphertext"])
            size_data = struct.pack("!I", total_size)
            
            # Enviar datos
            self.writer.write(size_data)
            self.writer.write(encrypted["nonce"])
            self.writer.write(encrypted["ciphertext"])
            await self.writer.drain()
            
            # Actualizar estadísticas
            self.bytes_sent += len(packet)
            self._update_status("stats_update")
            
        except Exception as e:
            logger.error(f"Error enviando paquete al servidor: {str(e)}")
            if self.running:
                # Solo intentar desconectar si aún estamos conectados
                asyncio.create_task(self.disconnect())
    
    async def _add_route(self, subnet: str):
        """
        Añade una ruta para dirigir tráfico a través de la VPN.
        
        Args:
            subnet: Subred en formato CIDR
        """
        try:
            # Implementación para Linux
            cmd = f"ip route add {subnet} dev {self.tun.name}"
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode != 0:
                logger.warning(f"Error al agregar ruta {subnet}: {stderr.decode()}")
            else:
                logger.info(f"Ruta agregada: {subnet}")
        
        except Exception as e:
            logger.error(f"Error al agregar ruta: {str(e)}")
    
    async def _send_data(self, data: bytes):
        """
        Envía datos con prefijo de longitud.
        
        Args:
            data: Datos a enviar
        """
        size = struct.pack("!I", len(data))
        self.writer.write(size)
        self.writer.write(data)
        await self.writer.drain()
    
    async def _receive_data(self) -> bytes:
        """
        Recibe datos con prefijo de longitud.
        
        Returns:
            Datos recibidos
        """
        # Leer tamaño (4 bytes, entero de red)
        size_data = await self.reader.readexactly(4)
        size = struct.unpack("!I", size_data)[0]
        
        # Leer datos
        data = await self.reader.readexactly(size)
        return data
    
    def get_status(self) -> Dict[str, Any]:
        """
        Obtiene el estado actual de la conexión VPN.
        
        Returns:
            Estado de la conexión
        """
        if not self.running:
            return {
                "connected": False,
                "uptime": 0,
                "bytesReceived": 0,
                "bytesSent": 0,
                "vpnIp": None,
                "server": None
            }
        
        # Calcular tiempo de conexión
        uptime = int(time.time() - self.connection_time)
        
        return {
            "connected": True,
            "uptime": uptime,
            "bytesReceived": self.bytes_received,
            "bytesSent": self.bytes_sent,
            "vpnIp": self.vpn_ip,
            "server": f"{self.server_host}:{self.server_port}"
        }
    
    def _update_status(self, event_type: str):
        """
        Notifica cambios de estado mediante callback.
        
        Args:
            event_type: Tipo de evento de estado
        """
        if self.status_callback:
            status = self.get_status()
            status["event"] = event_type
            self.status_callback(status)

# Crear instancia global
vpn_client = VPNClient()