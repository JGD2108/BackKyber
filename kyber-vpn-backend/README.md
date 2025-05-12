Set-Content -Path "kyber-vpn-backend\README.md" -Value @"
# Kyber VPN Backend

Backend para una VPN educativa resistente a ataques cuánticos utilizando CRYSTALS-Kyber para
el intercambio de claves y AES-256-GCM para el cifrado simétrico.

## Requisitos

- Python 3.9+
- Dependencias listadas en requirements.txt
- Permisos para crear interfaces de red (TUN/TAP)

## Instalación

1. Crear un entorno virtual: python -m venv venv 

2. Activar el entorno virtual: .\venv\Scripts\Activate