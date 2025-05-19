#!/usr/bin/env python3
"""
Script para ejecutar el servidor VPN real.

Este script verifica los requisitos necesarios y ejecuta el servidor VPN
con los privilegios adecuados.
"""
import os
import sys
import platform
import subprocess
import argparse
import urllib.request
import json
import logging

# Setup logging - Azure best practice for diagnostics
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='/var/log/kyber-vpn.log',
    filemode='a'
)
logger = logging.getLogger('kyber_vpn')

def is_azure_vm():
    """Detecta si estamos ejecutando en Azure VM."""
    try:
        req = urllib.request.Request(
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            headers={"Metadata": "true"}
        )
        response = urllib.request.urlopen(req, timeout=2)
        return response.getcode() == 200
    except Exception:
        return False

def check_requirements():
    """Verifica si se cumplen los requisitos para ejecutar la VPN real."""
    # Verificar sistema operativo
    os_name = platform.system().lower()
    if os_name not in ["linux", "windows"]:
        print(f"Sistema operativo no soportado: {platform.system()}")
        print("Se requiere Linux o Windows para ejecutar una VPN real.")
        return False
    
    # Verificar si se tienen privilegios de administrador
    is_admin = False
    try:
        if os_name == "windows":
            # En Windows, verificar membresía en grupo de administradores
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            # En Unix/Linux, verificar si el UID es 0 (root)
            is_admin = os.geteuid() == 0
    except:
        pass
    
    if not is_admin:
        print("No se tienen privilegios de administrador.")
        print("Se requieren privilegios de administrador para crear interfaces TUN/TAP.")
        if os_name == "linux":
            print("Ejecuta este script con 'sudo python3 run_vpn_server.py'")
        elif os_name == "windows":
            print("Ejecuta este script desde un CMD con privilegios de administrador.")
        return False
    
    # Verificar si se puede acceder a interfaces TUN/TAP
    if os_name == "linux":
        if not os.path.exists("/dev/net/tun"):
            print("No se encuentra el dispositivo TUN/TAP en /dev/net/tun")
            print("Asegúrate de que el módulo tun está cargado (modprobe tun)")
            return False
        
        if not os.access("/dev/net/tun", os.R_OK | os.W_OK):
            print("No se tienen permisos para acceder a /dev/net/tun")
            return False
    
    elif os_name == "windows":
        # En Windows, verificar si está instalado el driver TAP de OpenVPN
        try:
            result = subprocess.run(
                "netsh interface show interface", 
                capture_output=True, 
                text=True, 
                shell=True
            )
            if "TAP-Windows" not in result.stdout:
                print("No se encontró el adaptador TAP-Windows")
                print("Instala OpenVPN para obtener el driver TAP-Windows: https://openvpn.net/community-downloads/")
                return False
        except Exception as e:
            print(f"Error al verificar adaptadores de red: {str(e)}")
            return False
    
    # Verificar que no estamos en un entorno cloud restrictivo (excepto Azure)
    is_azure = is_azure_vm()
    if any(env in os.environ for env in ["RENDER", "VERCEL", "HEROKU_APP_ID"]) and not is_azure:
        print("Detectado entorno cloud que no permite crear interfaces TUN/TAP")
        print("Ejecuta este script en un servidor dedicado, VPS o máquina local")
        return False
    
    if is_azure:
        print("Detectado entorno Azure VM - compatible con VPN")
        if not configure_azure_environment():
            print("Error al configurar entorno Azure")
            return False
    
    return True

def configure_azure_environment():
    """Configure Azure VM environment for optimal VPN performance with Kyber."""
    if not is_azure_vm():
        return True
        
    logger.info("Configuring Azure environment for VPN with Kyber...")
    os_name = platform.system().lower()
    
    try:
        # 1. Install liboqs and dependencies for real Kyber
        if os_name == "linux":
            logger.info("Installing liboqs and dependencies")
            try:
                # Install build dependencies
                subprocess.run([
                    "/usr/bin/sudo", "apt-get", "update"
                ], check=True)
                
                subprocess.run([
                    "/usr/bin/sudo", "apt-get", "install", "-y", 
                    "build-essential", "cmake", "ninja-build", "python3-pip",
                    "libssl-dev", "python3-pytest", "python3-pytest-xdist",
                    "unzip", "xsltproc", "doxygen", "graphviz"
                ], check=True)
                
                # Check if liboqs is already installed
                liboqs_check = subprocess.run(
                    ["pip3", "show", "liboqs"], 
                    capture_output=True, 
                    text=True
                )
                
                if "not found" in liboqs_check.stderr or liboqs_check.returncode != 0:
                    logger.info("Installing liboqs")
                    # Clone and build liboqs
                    subprocess.run([
                        "git", "clone", "--depth", "1", 
                        "https://github.com/open-quantum-safe/liboqs.git",
                        "/tmp/liboqs"
                    ], check=True)
                    
                    # Build and install
                    subprocess.run([
                        "mkdir", "-p", "/tmp/liboqs/build"
                    ], check=True)
                    
                    subprocess.run([
                        "cmake", "-GNinja", "-DBUILD_SHARED_LIBS=ON",
                        "-S", "/tmp/liboqs", "-B", "/tmp/liboqs/build"
                    ], check=True)
                    
                    subprocess.run([
                        "ninja", "-j", "4"
                    ], cwd="/tmp/liboqs/build", check=True)
                    
                    subprocess.run([
                        "/usr/bin/sudo", "ninja", "install"
                    ], cwd="/tmp/liboqs/build", check=True)
                    
                    # Install Python wrapper
                    subprocess.run([
                        "/usr/bin/sudo", "pip3", "install", "/tmp/liboqs/build/python"
                    ], check=True)
                    
                    logger.info("liboqs installed successfully")
                else:
                    logger.info("liboqs already installed")
            except Exception as e:
                logger.warning(f"Could not install liboqs: {e}")
                logger.warning("Falling back to simulated Kyber mode")
        
        # 2. Enable IP forwarding for VPN traffic
        if os_name == "linux":
            subprocess.run(["/usr/bin/sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
            
            # Make IP forwarding persistent
            subprocess.run(["/usr/bin/sudo", "sh", "-c", "echo net.ipv4.ip_forward=1 > /etc/sysctl.d/99-vpn-forward.conf"], check=True)
            subprocess.run(["/usr/bin/sudo", "sysctl", "-p", "/etc/sysctl.d/99-vpn-forward.conf"], check=True)
            
            # 3. Configure iptables for NAT (required for VPN)
            subprocess.run([
                "/usr/bin/sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", 
                "-s", "10.8.0.0/24", "-o", "eth0", "-j", "MASQUERADE"
            ], check=True)
            
            # 4. Make iptables rules persistent
            try:
                subprocess.run(["/usr/bin/sudo", "apt-get", "install", "-y", "iptables-persistent"], check=True)
                subprocess.run(["/usr/bin/sudo", "netfilter-persistent", "save"], check=True)
            except Exception as e:
                logger.warning(f"Could not persist iptables rules: {e}")
            
            # 5. Install OpenVPN if not already installed
            try:
                openvpn_check = subprocess.run(
                    ["dpkg", "-l", "openvpn"], 
                    capture_output=True, 
                    text=True
                )
                
                if "no packages found" in openvpn_check.stdout or openvpn_check.returncode != 0:
                    logger.info("Installing OpenVPN")
                    subprocess.run([
                        "/usr/bin/sudo", "apt-get", "install", "-y", "openvpn"
                    ], check=True)
                else:
                    logger.info("OpenVPN already installed")
            except Exception as e:
                logger.warning(f"Could not install OpenVPN: {e}")
        
        return True
    except Exception as e:
        logger.error(f"Failed to configure Azure environment: {e}")
        return False

def run_vpn_server(port=1194, subnet="10.8.0.0/24", debug=False):
    """Ejecuta el servidor VPN real."""
    os_name = platform.system().lower()
    
    env = os.environ.copy()
    env["VPN_MODE"] = "real"
    env["VPN_PORT"] = str(port)
    env["VPN_SUBNET"] = subnet
    env["DEBUG"] = "true" if debug else "false"
    
    try:
        # Construir comando para ejecutar el servidor
        if os_name == "linux":
            cmd = [sys.executable, "-m", "app.network.vpn_server"]
        elif os_name == "windows":
            cmd = [sys.executable, "-m", "app.network.vpn_server"]
        
        # Ejecutar el servidor VPN
        print(f"Iniciando servidor VPN en puerto {port} con subred {subnet}")
        subprocess.run(cmd, env=env, check=True)
    
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar el servidor VPN: {e}")
        return False
    except KeyboardInterrupt:
        print("\nServidor VPN detenido")
    except Exception as e:
        print(f"Error inesperado: {str(e)}")
        return False
    
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Servidor VPN con cifrado post-cuántico")
    parser.add_argument("--port", type=int, default=1194, help="Puerto para el servidor VPN")
    parser.add_argument("--subnet", default="10.8.0.0/24", help="Subred para la VPN en formato CIDR")
    parser.add_argument("--debug", action="store_true", help="Habilitar modo de depuración")
    
    args = parser.parse_args()
    
    if check_requirements():
        print("Requisitos verificados correctamente")
        configure_azure_environment()
        run_vpn_server(port=args.port, subnet=args.subnet, debug=args.debug)
    else:
        sys.exit(1)