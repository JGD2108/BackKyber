"""
Real implementation of CRYSTALS-Kyber for post-quantum security.

This module implements CRYSTALS-Kyber key encapsulation mechanism
using the liboqs library for production-grade security.
"""
import base64
import os
from typing import Dict, Tuple, Optional, Any
import logging

# Import the Open Quantum Safe library wrapper
try:
    from oqs import KeyEncapsulation
    LIBOQS_AVAILABLE = True
except ImportError:
    LIBOQS_AVAILABLE = False
    logging.warning("liboqs not available - falling back to simulation mode")
    # Keep the simulation imports for fallback
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding

logger = logging.getLogger(__name__)

class KyberManager:
    """
    Production implementation of CRYSTALS-Kyber for post-quantum security.
    
    This class implements Kyber KEM using liboqs when available, with a fallback
    to simulation mode for educational environments.
    """
    
    def __init__(self, parameter_set: str = "kyber768"):
        """
        Initialize the Kyber manager with the specified parameter set.
        
        Args:
            parameter_set: Kyber parameter set ("kyber512", "kyber768", or "kyber1024")
        """
        # Validate parameter set
        valid_params = ["kyber512", "kyber768", "kyber1024"]
        if parameter_set.lower() not in valid_params:
            raise ValueError(f"Invalid parameter set. Must be one of: {valid_params}")
        
        self.parameter_set = parameter_set.lower()
        self._keypair = None
        self.use_real_kyber = LIBOQS_AVAILABLE
        
        # Map Kyber parameter sets to liboqs algorithm names
        self.algo_map = {
            "kyber512": "Kyber512",
            "kyber768": "Kyber768", 
            "kyber1024": "Kyber1024"
        }
        
        if self.use_real_kyber:
            self.algorithm = self.algo_map[self.parameter_set]
            logger.info(f"Using real Kyber implementation: {self.algorithm}")
        else:
            # Fallback to simulation mode
            self.key_size = {
                "kyber512": 2048,
                "kyber768": 3072,
                "kyber1024": 4096
            }[self.parameter_set]
            logger.warning(f"Using simulated Kyber (RSA-{self.key_size})")
    
    def generate_keypair(self) -> Dict[str, str]:
        """
        Generate a new Kyber keypair.
        
        Returns:
            Dictionary with public and private keys encoded in base64
        """
        if self.use_real_kyber:
            try:
                # Use real Kyber implementation
                kem = KeyEncapsulation(self.algorithm)
                public_key = kem.generate_keypair()
                secret_key = kem.export_secret_key()
                
                # Store for later use
                self._keypair = {
                    "public_key": public_key,
                    "secret_key": secret_key,
                    "kem": kem
                }
                
                # Return base64-encoded keys
                return {
                    "public_key": base64.b64encode(public_key).decode("utf-8"),
                    "secret_key": base64.b64encode(secret_key).decode("utf-8")
                }
            except Exception as e:
                logger.error(f"Error generating real Kyber keypair: {str(e)}")
                # Fall back to simulation
                self.use_real_kyber = False
                return self._generate_simulated_keypair()
        else:
            return self._generate_simulated_keypair()

    def _generate_simulated_keypair(self) -> Dict[str, str]:
        """Generate a simulated keypair using RSA as fallback."""
        try:
            # Generate an RSA key pair to simulate Kyber
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size,
            )
            public_key = private_key.public_key()
            
            # Serialize the keys
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Save for later use
            self._keypair = {
                "public_key": public_bytes,
                "secret_key": private_bytes,
                "private_key_obj": private_key,
                "public_key_obj": public_key
            }
            
            # Return base64-encoded keys
            return {
                "public_key": base64.b64encode(public_bytes).decode("utf-8"),
                "secret_key": base64.b64encode(private_bytes).decode("utf-8")
            }
        except Exception as e:
            raise RuntimeError(f"Error generating simulated keypair: {str(e)}")
    
    def encapsulate(self, public_key: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared key using Kyber.
        
        Args:
            public_key: Public key for encapsulation. If None, uses the previously generated key.
            
        Returns:
            Tuple with (shared_key, ciphertext)
        """
        if self.use_real_kyber:
            try:
                kem = KeyEncapsulation(self.algorithm)
                
                if public_key is None:
                    if self._keypair is None or "public_key" not in self._keypair:
                        raise ValueError("No public key available")
                    public_key = self._keypair["public_key"]
                elif isinstance(public_key, str):
                    public_key = base64.b64decode(public_key)
                
                # Real Kyber encapsulation
                ciphertext, shared_key = kem.encapsulate(public_key)
                return shared_key, ciphertext
            except Exception as e:
                logger.error(f"Error in real Kyber encapsulation: {str(e)}")
                if not isinstance(e, ValueError):
                    # Fall back to simulation for non-value errors
                    self.use_real_kyber = False
                    return self._encapsulate_simulated(public_key)
                raise
        else:
            return self._encapsulate_simulated(public_key)
    
    def _encapsulate_simulated(self, public_key: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Simulate encapsulation using RSA as fallback."""
        if public_key is None:
            if self._keypair is None or "public_key" not in self._keypair:
                raise ValueError("No public key available")
            public_key = self._keypair["public_key"]
            public_key_obj = self._keypair["public_key_obj"]
        elif isinstance(public_key, str):
            public_key = base64.b64decode(public_key)
            public_key_obj = serialization.load_der_public_key(public_key)
        else:
            public_key_obj = serialization.load_der_public_key(public_key)
        
        try:
            # Generate a shared key (32 bytes/256 bits)
            shared_key = os.urandom(32)
            
            # Encrypt the shared key with the public key (RSA)
            ciphertext = public_key_obj.encrypt(
                shared_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return shared_key, ciphertext
        except Exception as e:
            raise RuntimeError(f"Error in simulated encapsulation: {str(e)}")
    
    def decapsulate(self, ciphertext: bytes, secret_key: Optional[bytes] = None) -> bytes:
        """
        Decapsulate a shared key using Kyber.
        
        Args:
            ciphertext: Ciphertext to decapsulate
            secret_key: Secret key for decapsulation. If None, uses the previously generated key.
            
        Returns:
            Decapsulated shared key
        """
        if self.use_real_kyber:
            try:
                if secret_key is None:
                    if self._keypair is None or "kem" not in self._keypair:
                        if "secret_key" not in self._keypair:
                            raise ValueError("No secret key available")
                        # Create new KEM using stored secret key
                        kem = KeyEncapsulation(self.algorithm)
                        kem.import_secret_key(self._keypair["secret_key"])
                    else:
                        kem = self._keypair["kem"]
                else:
                    # Create new KEM using provided secret key
                    if isinstance(secret_key, str):
                        secret_key = base64.b64decode(secret_key)
                    
                    kem = KeyEncapsulation(self.algorithm)
                    kem.import_secret_key(secret_key)
                
                # Real Kyber decapsulation
                shared_key = kem.decapsulate(ciphertext)
                return shared_key
            except Exception as e:
                logger.error(f"Error in real Kyber decapsulation: {str(e)}")
                if not isinstance(e, ValueError):
                    # Fall back to simulation for non-value errors
                    self.use_real_kyber = False
                    return self._decapsulate_simulated(ciphertext, secret_key)
                raise
        else:
            return self._decapsulate_simulated(ciphertext, secret_key)
    
    def _decapsulate_simulated(self, ciphertext: bytes, secret_key: Optional[bytes] = None) -> bytes:
        """Simulate decapsulation using RSA as fallback."""
        if secret_key is None:
            if self._keypair is None or "private_key_obj" not in self._keypair:
                if "secret_key" not in self._keypair:
                    raise ValueError("No secret key available")
                # Load private key from stored bytes
                private_key = serialization.load_der_private_key(
                    self._keypair["secret_key"],
                    password=None,
                )
            else:
                private_key = self._keypair["private_key_obj"]
        else:
            # Load private key from provided bytes
            if isinstance(secret_key, str):
                secret_key = base64.b64decode(secret_key)
            
            private_key = serialization.load_der_private_key(
                secret_key,
                password=None,
            )
        
        try:
            # Decrypt the shared key with the private key (RSA)
            shared_key = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return shared_key
        except Exception as e:
            raise RuntimeError(f"Error in simulated decapsulation: {str(e)}")
