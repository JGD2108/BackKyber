"""
Implementación simulada de CRYSTALS-Kyber para fines educativos.

Este módulo simula el funcionamiento del algoritmo CRYSTALS-Kyber
para el intercambio de claves resistente a ataques cuánticos.
"""
import base64
import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from typing import Dict, Tuple, Optional, Any

class KyberManager:
    """
    Implementación simulada de CRYSTALS-Kyber para fines educativos.
    
    Esta clase simula el comportamiento de Kyber para propósitos educativos,
    aunque en realidad usa RSA bajo el capó. En una implementación real se
    utilizaría una biblioteca post-cuántica completa.
    """
    
    def __init__(self, parameter_set: str = "kyber768"):
        """
        Inicializa el gestor Kyber simulado.
        
        Args:
            parameter_set: Conjunto de parámetros simulados
                           ("kyber512", "kyber768", o "kyber1024")
        """
        # Validar el conjunto de parámetros
        valid_params = ["kyber512", "kyber768", "kyber1024"]
        if parameter_set.lower() not in valid_params:
            raise ValueError(f"Conjunto de parámetros inválido. Debe ser uno de: {valid_params}")
        
        self.parameter_set = parameter_set.lower()
        
        # Mapear parámetros de Kyber a tamaños de clave RSA para simular
        key_sizes = {
            "kyber512": 2048,   # Nivel de seguridad 1
            "kyber768": 3072,   # Nivel de seguridad 3
            "kyber1024": 4096,  # Nivel de seguridad 5
        }
        
        self.key_size = key_sizes[self.parameter_set]
        self._keypair = None
    
    def generate_keypair(self) -> Dict[str, str]:
        """
        Genera un nuevo par de claves simulado.
        
        Returns:
            Diccionario con claves pública y privada codificadas en base64
        """
        try:
            # Generar un par de claves RSA para simular Kyber
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size,
            )
            public_key = private_key.public_key()
            
            # Serializar las claves
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Guardar para uso posterior
            self._keypair = {
                "public_key": public_bytes,
                "secret_key": private_bytes,
                "private_key_obj": private_key,
                "public_key_obj": public_key
            }
            
            # Devolver claves codificadas en base64
            return {
                "public_key": base64.b64encode(public_bytes).decode("utf-8"),
                "secret_key": base64.b64encode(private_bytes).decode("utf-8")
            }
        except Exception as e:
            raise RuntimeError(f"Error al generar par de claves simulado: {str(e)}")
    
    def encapsulate(self, public_key: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Simula la encapsulación de una clave compartida.
        
        Args:
            public_key: Clave pública para encapsular. Si es None, usa la generada previamente.
            
        Returns:
            Tupla con (clave_compartida, ciphertext)
        """
        if public_key is None:
            if self._keypair is None or "public_key" not in self._keypair:
                raise ValueError("No hay clave pública disponible")
            public_key = self._keypair["public_key"]
            public_key_obj = self._keypair["public_key_obj"]
        else:
            # Cargar la clave pública desde bytes
            public_key_obj = serialization.load_der_public_key(public_key)
        
        try:
            # Generar una clave compartida aleatoria de 32 bytes (256 bits)
            shared_key = os.urandom(32)
            
            # Cifrar la clave compartida con la clave pública
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
            raise RuntimeError(f"Error al encapsular clave compartida: {str(e)}")
    
    def decapsulate(self, ciphertext: bytes, secret_key: Optional[bytes] = None) -> bytes:
        """
        Simula la desencapsulación de una clave compartida.
        
        Args:
            ciphertext: Ciphertext recibido
            secret_key: Clave secreta para desencapsular. Si es None, usa la generada previamente.
            
        Returns:
            Clave compartida desencapsulada
        """
        if secret_key is None:
            if self._keypair is None or "private_key_obj" not in self._keypair:
                raise ValueError("No hay clave secreta disponible")
            private_key = self._keypair["private_key_obj"]
        else:
            # Cargar la clave privada desde bytes
            private_key = serialization.load_der_private_key(
                secret_key,
                password=None,
            )
        
        try:
            # Descifrar la clave compartida con la clave privada
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
            raise RuntimeError(f"Error al desencapsular clave compartida: {str(e)}")
    
    @staticmethod
    def get_algorithm_details(variant: str = "kyber768") -> Dict[str, Any]:
        """
        Obtiene detalles técnicos sobre el algoritmo CRYSTALS-Kyber.
        
        Args:
            variant: Variante de Kyber ("kyber512", "kyber768", o "kyber1024")
            
        Returns:
            Diccionario con información del algoritmo
        """
        # Información real sobre Kyber, aunque estemos usando una simulación
        details = {
            "kyber512": {
                "name": "CRYSTALS-Kyber-512",
                "claimed_nist_level": 1,
                "public_key_length": 800,
                "secret_key_length": 1632,
                "ciphertext_length": 768,
                "shared_key_length": 32
            },
            "kyber768": {
                "name": "CRYSTALS-Kyber-768",
                "claimed_nist_level": 3,
                "public_key_length": 1184,
                "secret_key_length": 2400,
                "ciphertext_length": 1088,
                "shared_key_length": 32
            },
            "kyber1024": {
                "name": "CRYSTALS-Kyber-1024",
                "claimed_nist_level": 5,
                "public_key_length": 1568,
                "secret_key_length": 3168,
                "ciphertext_length": 1568,
                "shared_key_length": 32
            }
        }
        
        variant_key = variant.lower()
        if variant_key not in details:
            variant_key = "kyber768"  # Valor por defecto
            
        result = details[variant_key]
        result["version"] = "Simulación educativa"
        result["is_kem"] = True
        result["note"] = "Esta es una simulación educativa de Kyber usando RSA"
        
        return result
