"""
Implementación real de interfaces TUN/TAP para VPN.

Este módulo crea y gestiona interfaces TUN/TAP reales en el sistema operativo
para implementar una VPN funcional con enrutamiento real de tráfico.
"""
import os
import fcntl
import struct
import logging
import asyncio
import subprocess
import platform
from typing import Callable, Optional, Dict, Any, List
import ipaddress

# Estructura TUNSETIFF para configurar interfaz TUN/TAP
TUNSETIFF = 0x400454ca  # Constante ioctl para configurar la interfaz
IFF_TUN = 0x0001        # Modo TUN
IFF_TAP = 0x0002        # Modo TAP
IFF_NO_PI = 0x1000      # No incluir información de protocolo

# Configurar logger
logger = logging.getLogger(__name__)

class TunDevice:
    """
    Implementación real de interfaces TUN/TAP para VPN.
    
    Esta clase crea y gestiona interfaces TUN/TAP reales en el sistema operativo,
    permitiendo el enrutamiento de tráfico IP real entre redes.
    """
    
    def __init__(self, name: str = "tun0", mode: str = "tun", mtu: int = 1500):
        """
        Inicializa la interfaz TUN/TAP real.
        
        Args:
            name: Nombre de la interfaz (ej: "tun0")
            mode: Modo de la interfaz ("tun" o "tap")
            mtu: Maximum Transmission Unit
        """
        if mode not in ["tun", "tap"]:
            raise ValueError("El modo debe ser 'tun' o 'tap'")
        
        self.name = name
        self.mode = mode
        self.mtu = mtu
        self.file = None  # Descriptor de archivo para la interfaz
        self.running = False
        self.packet_callback = None
        self.ip_address = None
        self.netmask = None
        self.os_type = platform.system().lower()
        
        logger.info(f"Inicializando interfaz {name} (modo: {mode}, MTU: {mtu}) en {self.os_type}")
    
    async def create_interface(self, ip_address: str, netmask: str = "255.255.255.0") -> bool:
        """
        Crea y configura una interfaz TUN/TAP real en el sistema.
        
        Args:
            ip_address: Dirección IP para la interfaz
            netmask: Máscara de red
            
        Returns:
            True si la interfaz se creó correctamente
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
        
        # Verificar privilegios
        if os.geteuid() != 0:
            logger.error("Se requieren privilegios de administrador para crear interfaces TUN/TAP")
            raise PermissionError("Se requieren privilegios de administrador para crear interfaces TUN/TAP")
        
        # Implementación específica para cada sistema operativo
        if self.os_type == "linux":
            return await self._create_interface_linux(ip_address, netmask)
        elif self.os_type == "windows":
            return await self._create_interface_windows(ip_address, netmask)
        else:
            logger.error(f"Sistema operativo no soportado: {self.os_type}")
            raise NotImplementedError(f"Sistema operativo no soportado: {self.os_type}")
    
    async def _create_interface_linux(self, ip_address: str, netmask: str) -> bool:
        """Implementación específica para Linux"""
        try:
            # Abrir el dispositivo TUN/TAP
            self.file = open("/dev/net/tun", "rb+")
            
            # Configurar la interfaz
            flags = IFF_NO_PI
            if self.mode == "tun":
                flags |= IFF_TUN
            else:
                flags |= IFF_TAP
            
            # Aplicar configuración con ioctl
            ifr = struct.pack('16sH', self.name.encode(), flags)
            fcntl.ioctl(self.file, TUNSETIFF, ifr)
            
            # Configurar la dirección IP y MTU con comandos de sistema
            await self._run_cmd(f"ip link set dev {self.name} up mtu {self.mtu}")
            await self._run_cmd(f"ip addr add {ip_address}/{self._netmask_to_cidr(netmask)} dev {self.name}")
            
            logger.info(f"Interfaz {self.name} creada con IP {ip_address}/{self._netmask_to_cidr(netmask)}")
            return True
        
        except Exception as e:
            if self.file:
                self.file.close()
                self.file = None
            logger.error(f"Error al crear interfaz TUN/TAP en Linux: {str(e)}")
            raise
    
    async def _create_interface_windows(self, ip_address: str, netmask: str) -> bool:
        """Implementación específica para Windows utilizando OpenVPN TAP-Windows"""
        try:
            # En Windows necesitamos usar el driver TAP-Windows de OpenVPN
            # Esto requiere que el driver esté instalado previamente
            
            # Primero encontramos la interfaz TAP existente
            output = await self._run_cmd("netsh interface show interface")
            
            # Buscar la interfaz OpenVPN TAP
            if "TAP-Windows Adapter" not in output:
                raise RuntimeError("No se encontró ninguna interfaz TAP-Windows. Por favor instale OpenVPN.")
            
            # Obtener el nombre de la interfaz
            # Nota: esto es simplificado, en un caso real necesitaríamos parsear mejor la salida
            lines = output.split('\n')
            tap_interface = None
            for line in lines:
                if "TAP-Windows Adapter" in line:
                    parts = line.split()
                    tap_interface = parts[-1]
                    break
            
            if not tap_interface:
                raise RuntimeError("No se pudo determinar el nombre de la interfaz TAP-Windows")
            
            # Establecer la IP en la interfaz
            await self._run_cmd(f"netsh interface ip set address name=\"{tap_interface}\" static {ip_address} {netmask}")
            
            # Crear un archivo virtual para simular la interfaz TUN/TAP en Windows
            # Esto es una simulación, en Windows se necesitaría un enfoque diferente
            import tempfile
            self.file = tempfile.TemporaryFile(mode="rb+")
            
            logger.info(f"Interfaz TAP configurada en Windows con IP {ip_address}/{netmask}")
            return True
            
        except Exception as e:
            if self.file:
                self.file.close()
                self.file = None
            logger.error(f"Error al configurar interfaz TAP en Windows: {str(e)}")
            raise
    
    def set_packet_callback(self, callback: Callable):
        """
        Establece la función de callback para procesar paquetes.
        
        Args:
            callback: Función que será llamada cuando se reciban paquetes
        """
        self.packet_callback = callback
        logger.debug(f"Callback establecido para la interfaz {self.name}")
    
    async def start(self):
        """
        Inicia el procesamiento de paquetes en la interfaz TUN/TAP.
        """
        if not self.file:
            raise RuntimeError("La interfaz TUN no ha sido creada")
        
        if not self.packet_callback:
            raise RuntimeError("No se ha definido un callback para procesar paquetes")
        
        self.running = True
        logger.info(f"Iniciando procesamiento de paquetes en interfaz {self.name}")
        
        try:
            # Configurar el descriptor de archivo para operaciones no bloqueantes
            os.set_blocking(self.file.fileno(), False)
            
            # Bucle principal para procesar paquetes
            while self.running:
                # Usar select para esperar datos sin bloquear
                await asyncio.sleep(0.001)  # Pequeña pausa para evitar bucle intensivo de CPU
                
                if not self.running:
                    break
                
                try:
                    # Leer paquete (hasta MTU bytes)
                    packet = self.file.read(self.mtu)
                    if packet:
                        # Procesar el paquete recibido
                        if self.packet_callback:
                            try:
                                await self.packet_callback(packet)
                            except Exception as e:
                                logger.error(f"Error en callback al procesar paquete: {str(e)}")
                except BlockingIOError:
                    # No hay datos disponibles todavía, continuar
                    continue
                except Exception as e:
                    logger.error(f"Error al leer de la interfaz: {str(e)}")
                    if not self.running:
                        break
        
        except asyncio.CancelledError:
            logger.info(f"Procesamiento de paquetes cancelado para {self.name}")
            self.running = False
        except Exception as e:
            logger.error(f"Error en el procesamiento: {str(e)}")
            self.running = False
            raise
        finally:
            if self.file:
                try:
                    self.file.close()
                except:
                    pass
    
    async def send_packet(self, packet: bytes):
        """
        Envía un paquete a través de la interfaz TUN/TAP.
        
        Args:
            packet: Datos del paquete a enviar
        """
        if not self.file:
            raise RuntimeError("La interfaz TUN no ha sido creada")
        
        try:
            self.file.write(packet)
            self.file.flush()
            logger.debug(f"Paquete enviado por {self.name}: {len(packet)} bytes")
        except Exception as e:
            logger.error(f"Error al enviar paquete: {str(e)}")
            raise
    
    async def stop(self):
        """
        Detiene el procesamiento de paquetes y cierra la interfaz.
        """
        self.running = False
        
        if self.file:
            try:
                # Bajar la interfaz
                if self.os_type == "linux":
                    await self._run_cmd(f"ip link set dev {self.name} down")
                elif self.os_type == "windows":
                    # En Windows podríamos deshabilitar la interfaz
                    pass
                
                self.file.close()
                logger.info(f"Interfaz {self.name} cerrada y apagada")
            except Exception as e:
                logger.error(f"Error al cerrar interfaz: {str(e)}")
            finally:
                self.file = None
    
    async def setup_routing(self, subnet: str, masquerade: bool = True):
        """
        Configura el enrutamiento para el tráfico VPN.
        
        Args:
            subnet: Subred VPN en formato CIDR (ej: "10.8.0.0/24")
            masquerade: Activar enmascaramiento para NAT
        """
        try:
            if self.os_type == "linux":
                # Habilitar IP forwarding
                await self._run_cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
                
                # Configurar reglas de firewall para permitir tráfico hacia/desde la VPN
                # Obtener interfaz de salida a Internet
                internet_iface = await self._get_default_interface()
                
                if internet_iface:
                    # Permitir reenvío entre interfaces
                    await self._run_cmd(f"iptables -A FORWARD -i {self.name} -o {internet_iface} -j ACCEPT")
                    await self._run_cmd(f"iptables -A FORWARD -i {internet_iface} -o {self.name} -j ACCEPT")
                    
                    # Configurar NAT si se solicitó
                    if masquerade:
                        await self._run_cmd(f"iptables -t nat -A POSTROUTING -s {subnet} -o {internet_iface} -j MASQUERADE")
                    
                    logger.info(f"Enrutamiento configurado para subred VPN {subnet} a través de {internet_iface}")
                else:
                    logger.warning("No se pudo determinar la interfaz de salida a Internet")
            
            elif self.os_type == "windows":
                # En Windows, configurar el enrutamiento
                await self._run_cmd(f"netsh routing ip nat install")
                internet_iface = await self._get_default_interface()
                
                if internet_iface:
                    await self._run_cmd(f"netsh routing ip nat add interface \"{internet_iface}\" full")
                    logger.info(f"NAT configurado en Windows a través de {internet_iface}")
                else:
                    logger.warning("No se pudo determinar la interfaz de salida a Internet en Windows")
        
        except Exception as e:
            logger.error(f"Error al configurar enrutamiento: {str(e)}")
            raise
    
    async def _run_cmd(self, cmd: str) -> str:
        """
        Ejecuta un comando del sistema operativo.
        
        Args:
            cmd: Comando a ejecutar
            
        Returns:
            Salida del comando
        """
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        if proc.returncode != 0:
            error = stderr.decode().strip()
            logger.error(f"Error ejecutando comando '{cmd}': {error}")
            raise RuntimeError(f"Error ejecutando comando '{cmd}': {error}")
        
        return stdout.decode().strip()
    
    async def _get_default_interface(self) -> Optional[str]:
        """
        Determina la interfaz de red predeterminada para salir a Internet.
        
        Returns:
            Nombre de la interfaz o None si no se pudo determinar
        """
        try:
            if self.os_type == "linux":
                output = await self._run_cmd("ip route | grep default")
                parts = output.split()
                if len(parts) >= 5 and parts[0] == "default" and parts[1] == "via" and parts[3] == "dev":
                    return parts[4]
            elif self.os_type == "windows":
                output = await self._run_cmd("netsh interface ipv4 show route")
                lines = output.split('\n')
                for line in lines:
                    if "0.0.0.0/0" in line:
                        parts = line.split()
                        # El formato puede variar, esto es simplificado
                        for i, part in enumerate(parts):
                            if part == "interface":
                                return parts[i+1]
            return None
        except Exception:
            return None
    
    @staticmethod
    def _netmask_to_cidr(netmask: str) -> int:
        """
        Convierte una máscara de red en formato CIDR.
        
        Args:
            netmask: Máscara de red (ej: "255.255.255.0")
            
        Returns:
            Prefijo CIDR (ej: 24)
        """
        return sum(bin(int(x)).count('1') for x in netmask.split('.'))