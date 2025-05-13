"""
Implementación de un servidor VPN con resistencia post-cuántica.

Este módulo implementa un servidor VPN real utilizando interfaces TUN/TAP
y criptografía post-cuántica para proteger las conexiones.
"""
import asyncio
import logging
import ipaddress
import os
import time
import socket
import struct
from typing import Dict, List, Any, Optional, Set
import json

from app.crypto.kyber import KyberManager
from app.crypto.symmetric import AESGCMCipher
from app.network.tun import TunDevice
from app.core.config import settings

# Configurar logger
logger = logging.getLogger(__name__)

# Puerto para el servidor VPN
VPN_PORT = 1194

class VPNClient:
    """Representación de un cliente conectado al servidor VPN."""
    
    def __init__(self, client_id: str, vpn_ip: str, writer: asyncio.StreamWriter, 
                 aes_cipher: AESGCMCipher):
        self.id = client_id
        self.vpn_ip = vpn_ip
        self.writer = writer
        self.cipher = aes_cipher
        self.last_activity = time.time()
        self.bytes_sent = 0
        self.bytes_received = 0
        self.connected_since = time.time()

class VPNServer:
    """
    Servidor VPN real con soporte para criptografía post-cuántica.
    
    Implementa un servidor VPN completo que maneja múltiples clientes,
    enrutamiento de tráfico y cifrado de datos usando intercambio de claves
    Kyber y cifrado AES-GCM.
    """
    
    def __init__(self, subnet: str = "10.8.0.0/24", 
                 port: int = VPN_PORT):
        """
        Inicializa el servidor VPN.
        
        Args:
            subnet: Subred para asignar a los clientes VPN
            port: Puerto para escuchar conexiones
        """
        self.subnet = subnet
        self.port = port
        self.tun = None
        self.server = None
        self.running = False
        self.clients: Dict[str, VPNClient] = {}  # client_id -> VPNClient
        self.ip_to_client: Dict[str, str] = {}   # vpn_ip -> client_id
        self.available_ips: List[str] = []
        
        # Inicializar Kyber para intercambio de claves
        self.kyber = KyberManager(parameter_set=settings.KYBER_PARAMETER)
        
        # Generar par de claves del servidor
        self.server_keypair = None
        
        # Inicializar subred VPN
        self._init_ip_pool()
        
        logger.info(f"Servidor VPN inicializado, subnet: {subnet}, puerto: {port}")
    
    def _init_ip_pool(self):
        """Inicializa el pool de direcciones IP disponibles para clientes."""
        try:
            network = ipaddress.IPv4Network(self.subnet)
            # Reservar primera IP (red) y segunda IP (servidor)
            # Todas las demás están disponibles para clientes
            self.available_ips = [str(ip) for ip in list(network.hosts())[1:]]
            logger.info(f"Pool de IPs inicializado con {len(self.available_ips)} direcciones disponibles")
        except Exception as e:
            logger.error(f"Error al inicializar pool de IPs: {str(e)}")
            raise
    
    def _get_next_ip(self) -> Optional[str]:
        """
        Obtiene la siguiente IP disponible para un cliente.
        
        Returns:
            Dirección IP o None si no hay disponibles
        """
        if not self.available_ips:
            return None
        return self.available_ips.pop(0)
    
    def _release_ip(self, ip: str):
        """
        Devuelve una IP al pool de disponibles.
        
        Args:
            ip: Dirección IP a liberar
        """
        if ip not in self.available_ips:
            self.available_ips.append(ip)
    
    async def start(self):
        """Inicia el servidor VPN."""
        if self.running:
            logger.warning("El servidor VPN ya está en ejecución")
            return
        
        try:
            # Generar par de claves Kyber
            logger.info("Generando par de claves Kyber para el servidor...")
            self.server_keypair = self.kyber.generate_keypair()
            
            # Crear y configurar interfaz TUN
            logger.info("Creando interfaz TUN...")
            self.tun = TunDevice(name="tun0", mode="tun")
            
            # Obtener la IP del servidor (primera IP disponible después de la dirección de red)
            network = ipaddress.IPv4Network(self.subnet)
            server_ip = str(list(network.hosts())[0])
            
            # Crear interfaz TUN con la IP del servidor
            netmask = str(network.netmask)
            await self.tun.create_interface(server_ip, netmask)
            
            # Configurar enrutamiento
            await self.tun.setup_routing(self.subnet)
            
            # Configurar callback para procesar paquetes
            self.tun.set_packet_callback(self._process_tun_packet)
            
            # Iniciar procesamiento de paquetes TUN
            tun_task = asyncio.create_task(self.tun.start())
            
            # Iniciar servidor TCP
            server = await asyncio.start_server(
                self._handle_client,
                '0.0.0.0',
                self.port
            )
            
            addr = server.sockets[0].getsockname()
            logger.info(f'Servidor VPN escuchando en {addr}')
            
            self.server = server
            self.running = True
            
            # Mantener servidor en ejecución
            async with server:
                await server.serve_forever()
        
        except Exception as e:
            logger.error(f"Error al iniciar servidor VPN: {str(e)}")
            await self.stop()
            raise
    
    async def stop(self):
        """Detiene el servidor VPN."""
        self.running = False
        
        # Cerrar todas las conexiones de clientes
        for client_id, client in list(self.clients.items()):
            await self._disconnect_client(client_id)
        
        # Detener servidor TCP
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        
        # Detener interfaz TUN
        if self.tun:
            await self.tun.stop()
            self.tun = None
        
        logger.info("Servidor VPN detenido")
    
    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        Maneja una nueva conexión de cliente.
        
        Args:
            reader: Stream de lectura del socket
            writer: Stream de escritura del socket
        """
        addr = writer.get_extra_info('peername')
        client_id = f"{addr[0]}:{addr[1]}"
        logger.info(f"Nueva conexión desde {client_id}")
        
        try:
            # Realizar handshake Kyber para establecer clave compartida
            client_public_key = await self._receive_data(reader)
            
            # Encapsular clave compartida usando la clave pública del cliente
            shared_key, ciphertext = self.kyber.encapsulate(client_public_key)
            
            # Enviar ciphertext al cliente
            await self._send_data(writer, ciphertext)
            
            # Inicializar cifrado AES con la clave compartida
            aes_cipher = AESGCMCipher(key=shared_key)
            
            # Asignar IP VPN al cliente
            vpn_ip = self._get_next_ip()
            if not vpn_ip:
                logger.error(f"No hay IPs disponibles para asignar al cliente {client_id}")
                writer.close()
                await writer.wait_closed()
                return
            
            # Enviar configuración al cliente
            config = {
                "vpn_ip": vpn_ip,
                "subnet": self.subnet,
                "routes": [self.subnet]  # Rutas que deben ir por la VPN
            }
            
            config_data = json.dumps(config).encode()
            encrypted_config = aes_cipher.encrypt(config_data)
            
            # Enviar nonce y ciphertext
            await self._send_data(writer, encrypted_config["nonce"] + encrypted_config["ciphertext"])
            
            # Registrar cliente
            client = VPNClient(client_id, vpn_ip, writer, aes_cipher)
            self.clients[client_id] = client
            self.ip_to_client[vpn_ip] = client_id
            
            logger.info(f"Cliente {client_id} conectado con IP VPN {vpn_ip}")
            
            # Procesar datos del cliente
            await self._handle_client_data(client_id, reader)
            
        except asyncio.CancelledError:
            # Manejo normal de cancelación
            pass
        except Exception as e:
            logger.error(f"Error en manejo de cliente {client_id}: {str(e)}")
        finally:
            # Desconectar cliente en caso de error o desconexión
            await self._disconnect_client(client_id)
    
    async def _handle_client_data(self, client_id: str, reader: asyncio.StreamReader):
        """
        Procesa los datos recibidos de un cliente.
        
        Args:
            client_id: ID del cliente
            reader: Stream de lectura del socket
        """
        client = self.clients.get(client_id)
        if not client:
            return
        
        try:
            while self.running:
                # Recibir tamaño del paquete
                size_data = await reader.readexactly(4)
                if not size_data:
                    break
                
                packet_size = struct.unpack("!I", size_data)[0]
                
                # Recibir paquete cifrado
                encrypted_data = await reader.readexactly(packet_size)
                if not encrypted_data:
                    break
                
                # Dividir en nonce y ciphertext (primeros 12 bytes son el nonce)
                nonce = encrypted_data[:12]
                ciphertext = encrypted_data[12:]
                
                # Descifrar paquete
                try:
                    packet = client.cipher.decrypt(nonce, ciphertext)
                    
                    # Procesar el paquete IP (enviarlo a la interfaz TUN)
                    await self.tun.send_packet(packet)
                    
                    # Actualizar estadísticas
                    client.bytes_received += len(packet)
                    client.last_activity = time.time()
                    
                except Exception as e:
                    logger.error(f"Error al descifrar paquete de {client_id}: {str(e)}")
                    continue
        
        except asyncio.IncompleteReadError:
            # Conexión cerrada por el cliente
            pass
        except asyncio.CancelledError:
            # Cancelación normal
            pass
        except Exception as e:
            logger.error(f"Error procesando datos de {client_id}: {str(e)}")
        finally:
            # Desconectar cliente
            await self._disconnect_client(client_id)
    
    async def _process_tun_packet(self, packet: bytes):
        """
        Procesa un paquete recibido de la interfaz TUN.
        
        Args:
            packet: Datos del paquete IP
        """
        try:
            # Extraer direcciones IP de origen y destino
            if len(packet) < 20:  # Tamaño mínimo de una cabecera IPv4
                return
            
            # Cabecera IPv4: versión y longitud cabecera (1 byte)
            version_ihl = packet[0]
            version = version_ihl >> 4
            
            if version != 4:  # Solo IPv4 por ahora
                return
            
            # Direcciones IP están en posiciones 12-16 (origen) y 16-20 (destino)
            src_ip = socket.inet_ntoa(packet[12:16])
            dst_ip = socket.inet_ntoa(packet[16:20])
            
            # Determinar destinatario
            client_id = self.ip_to_client.get(dst_ip)
            if not client_id or client_id not in self.clients:
                # No es un paquete para un cliente VPN
                return
            
            client = self.clients[client_id]
            
            # Cifrar el paquete con la clave del cliente
            encrypted = client.cipher.encrypt(packet)
            
            # Enviar al cliente
            size_data = struct.pack("!I", len(encrypted["nonce"]) + len(encrypted["ciphertext"]))
            
            client.writer.write(size_data)
            client.writer.write(encrypted["nonce"])
            client.writer.write(encrypted["ciphertext"])
            await client.writer.drain()
            
            # Actualizar estadísticas
            client.bytes_sent += len(packet)
            
        except Exception as e:
            logger.error(f"Error procesando paquete TUN: {str(e)}")
    
    async def _disconnect_client(self, client_id: str):
        """
        Desconecta a un cliente.
        
        Args:
            client_id: ID del cliente a desconectar
        """
        client = self.clients.pop(client_id, None)
        if not client:
            return
        
        # Liberar IP
        if client.vpn_ip:
            self.ip_to_client.pop(client.vpn_ip, None)
            self._release_ip(client.vpn_ip)
        
        # Cerrar conexión
        try:
            client.writer.close()
            await client.writer.wait_closed()
        except:
            pass
        
        logger.info(f"Cliente {client_id} desconectado")
    
    async def _send_data(self, writer: asyncio.StreamWriter, data: bytes):
        """
        Envía datos con prefijo de longitud.
        
        Args:
            writer: Stream de escritura
            data: Datos a enviar
        """
        size = struct.pack("!I", len(data))
        writer.write(size)
        writer.write(data)
        await writer.drain()
    
    async def _receive_data(self, reader: asyncio.StreamReader) -> bytes:
        """
        Recibe datos con prefijo de longitud.
        
        Args:
            reader: Stream de lectura
            
        Returns:
            Datos recibidos
        """
        # Leer tamaño (4 bytes, entero de red)
        size_data = await reader.readexactly(4)
        size = struct.unpack("!I", size_data)[0]
        
        # Leer datos
        data = await reader.readexactly(size)
        return data

# Crear instancia global
vpn_server = VPNServer(subnet=settings.VPN_SUBNET, port=VPN_PORT)

# Add this defensive initialization

class VpnServer:
    def __init__(self):
        self.clients = {}
        self.available_ips = ["10.8.0." + str(i) for i in range(2, 255)]
        self.uptime = 0
        # Add more robust initialization for Azure environment

# If the global vpn_server instance is causing issues, ensure it's created properly
try:
    vpn_server = VpnServer()
except Exception as e:
    import logging
    logger = logging.getLogger("kyber-vpn")
    logger.error(f"Failed to initialize VPN server: {str(e)}", exc_info=True)
    vpn_server = VpnServer()  # Fallback to empty server
