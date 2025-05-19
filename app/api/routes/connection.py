"""
API routes for VPN connection management.

This module implements endpoints for connecting/disconnecting
the VPN and obtaining its current status.
"""
from asyncio.log import logger
from fastapi import APIRouter, HTTPException, Depends, Request
from typing import Dict, Any
import logging
import asyncio
import subprocess
import tempfile
import os
import json

from app.models.schemas import ConnectionRequest, ConnectionResponse, VpnStatus
from app.network.vpn_client import vpn_client
from app.core.config import settings
from app.crypto.kyber import KyberManager

logger = logging.getLogger("kyber-vpn")

router = APIRouter()

# Detailed logging for diagnostics, especially for Azure environments
@router.post("/connect")
async def connect_to_vpn(request: ConnectionRequest, req: Request):
    """
    Establishes a VPN connection with the specified server using Kyber KEM.
    
    Args:
        request: Connection data including the server ID
        
    Returns:
        Result of the connection operation
    """
    logger.info(f"Attempting to connect to VPN server: {request.serverId}")
    
    # Check for Azure-specific headers
    is_azure_client = req.headers.get("x-azure-client") == "true"
    if is_azure_client:
        logger.info("Connection from Azure client detected")
    
    try:
        # Detailed logging for server lookup
        logger.info(f"Looking for server with ID: {request.serverId}")
        available_servers = [s.get("id") for s in settings.VPN_SERVERS]
        logger.info(f"Available servers: {available_servers}")
        
        server = next((s for s in settings.VPN_SERVERS if s["id"] == request.serverId), None)
        if not server:
            logger.error(f"Server not found: {request.serverId}")
            raise HTTPException(status_code=404, detail="Server not found")
        
        # Choose connection method based on server configuration
        connection_type = server.get("connection_type", "internal")
        logger.info(f"Using connection type: {connection_type}")
        
        if connection_type == "openvpn":
            # Use OpenVPN with Kyber integration
            return await connect_with_openvpn(server, is_azure_client)
        else:
            # Use internal VPN implementation
            logger.info(f"Connecting to {server['ip']}:{server['port']}")
            
            # Add retry logic for Azure connections
            max_retries = 3 if is_azure_client else 1
            retry_count = 0
            last_error = None
            
            while retry_count < max_retries:
                try:
                    result = await vpn_client.connect(server["ip"], server["port"])
                    
                    if not result["success"]:
                        logger.error(f"Connection failed: {result['message']}")
                    else:
                        logger.info(f"Connection successful. VPN IP assigned: {result.get('vpnIp')}")
                    
                    return ConnectionResponse(**result)
                except Exception as e:
                    retry_count += 1
                    last_error = e
                    logger.warning(f"Attempt {retry_count} failed: {str(e)}")
                    if retry_count < max_retries:
                        await asyncio.sleep(1)  # Wait before retrying
            
            # If we get here, all retries failed
            raise last_error
        
    except Exception as e:
        logger.error(f"Error in VPN connection: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal error while connecting: {str(e)}")

async def connect_with_openvpn(server: Dict[str, Any], is_azure_client: bool = False) -> ConnectionResponse:
    """
    Establishes a VPN connection using OpenVPN with Kyber KEM integration.
    
    Args:
        server: Server configuration
        is_azure_client: Whether the request is from an Azure client
        
    Returns:
        Result of the connection operation
    """
    logger.info(f"Connecting to OpenVPN server: {server['ip']}:{server.get('openvpn_port', 1194)}")
    
    try:
        # Setup Kyber key exchange
        kyber = KyberManager(parameter_set=settings.KYBER_PARAMETER)
        keypair = kyber.generate_keypair()
        
        # Create temporary directory for OpenVPN configuration
        with tempfile.TemporaryDirectory() as tempdir:
            # Save client certificate and key
            client_key_path = os.path.join(tempdir, "client.key")
            client_cert_path = os.path.join(tempdir, "client.crt")
            ca_cert_path = os.path.join(tempdir, "ca.crt")
            
            # Save client Kyber public key for the handshake
            client_kyber_path = os.path.join(tempdir, "client_kyber.pem")
            with open(client_kyber_path, "w") as f:
                f.write(keypair["public_key"])
            
            # Create OpenVPN configuration
            config_path = os.path.join(tempdir, "client.ovpn")
            with open(config_path, "w") as f:
                f.write(f"""client
dev tun
proto udp
remote {server['ip']} {server.get('openvpn_port', 1194)}
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA384
tls-client
tls-version-min 1.2
tls-cipher TLS_AES_256_GCM_SHA384

# Custom script to handle Kyber key exchange
script-security 2
up "/etc/openvpn/client/kyber_up.sh {client_kyber_path}"

# Standard certs (traditional security layer)
key {client_key_path}
cert {client_cert_path}
ca {ca_cert_path}
""")
            
            # Import server's OpenVPN certificates
            with open(client_key_path, "w") as f:
                f.write(server.get("openvpn_client_key", ""))
            
            with open(client_cert_path, "w") as f:
                f.write(server.get("openvpn_client_cert", ""))
            
            with open(ca_cert_path, "w") as f:
                f.write(server.get("openvpn_ca_cert", ""))
            
            # Launch OpenVPN process with Kyber integration
            # In Azure, we need sudo
            cmd = ["sudo", "openvpn", "--config", config_path] if is_azure_client else ["openvpn", "--config", config_path]
            
            # Start OpenVPN in a new process
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Wait for connection (simplified - in real implementation, monitor the process output)
            await asyncio.sleep(5)
            
            # Verify connection succeeded
            if process.returncode is not None:
                # Process exited too quickly - connection failed
                stdout, stderr = await process.communicate()
                logger.error(f"OpenVPN connection failed: {stderr.decode()}")
                return ConnectionResponse(
                    success=False,
                    message=f"OpenVPN connection failed: {stderr.decode()}"
                )
            
            # Get assigned IP (this is simplified - in real implementation, parse OpenVPN logs)
            vpn_ip = "10.8.0.X"  # Placeholder
            
            return ConnectionResponse(
                success=True,
                message="Connected to VPN server via OpenVPN with Kyber KEM",
                vpnIp=vpn_ip
            )
    
    except Exception as e:
        logger.error(f"Error in OpenVPN connection: {str(e)}", exc_info=True)
        return ConnectionResponse(
            success=False,
            message=f"OpenVPN connection error: {str(e)}"
        )
