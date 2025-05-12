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
    
    # Verificar que no estamos en un entorno cloud restrictivo
    if any(env in os.environ for env in ["RENDER", "VERCEL", "HEROKU_APP_ID"]):
        print("Detectado entorno cloud que no permite crear interfaces TUN/TAP")
        print("Ejecuta este script en un servidor dedicado, VPS o máquina local")
        return False
    
    return True

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
        run_vpn_server(port=args.port, subnet=args.subnet, debug=args.debug)
    else:
        sys.exit(1)