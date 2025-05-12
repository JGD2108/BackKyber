"""
Implementación de cifrado simétrico con AES-256-GCM.

Este módulo proporciona funcionalidades para cifrar y descifrar datos
usando AES-256-GCM, un modo de cifrado autenticado que proporciona
tanto confidencialidad como integridad.
"""
import os
import base64
from typing import Dict, Optional, Union, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class AESGCMCipher:
    """
    Gestor para operaciones de cifrado con AES-256-GCM.
    
    Esta clase encapsula la funcionalidad de cifrado y descifrado
    utilizando AES-256 en modo GCM (Galois/Counter Mode).
    """
    
    def __init__(self, key: Optional[bytes] = None):
        """
        Inicializa el cifrador con una clave opcional.
        
        Args:
            key: Clave de 32 bytes para AES-256. Si es None, se genera aleatoriamente.
        """
        if key is None:
            # Generar clave aleatoria de 32 bytes (256 bits)
            self.key = os.urandom(32)
        else:
            if len(key) != 32:
                raise ValueError("La clave debe tener 32 bytes (256 bits) para AES-256")
            self.key = key
        
        # Inicializar el cifrador AESGCM
        self.cipher = AESGCM(self.key)
    
    def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> Dict[str, bytes]:
        """
        Cifra datos usando AES-256-GCM.
        
        Args:
            plaintext: Datos a cifrar
            associated_data: Datos adicionales autenticados (no cifrados)
            
        Returns:
            Diccionario con nonce y ciphertext
        """
        # Generar un nonce aleatorio de 12 bytes (96 bits)
        # IMPORTANTE: El nonce NUNCA debe reutilizarse con la misma clave
        nonce = os.urandom(12)
        
        try:
            # Cifrar los datos
            ciphertext = self.cipher.encrypt(nonce, plaintext, associated_data)
            
            # Devolver nonce y ciphertext
            return {
                "nonce": nonce,
                "ciphertext": ciphertext
            }
        except Exception as e:
            raise RuntimeError(f"Error al cifrar datos: {str(e)}")
    
    def decrypt(self, nonce: bytes, ciphertext: bytes, 
                associated_data: Optional[bytes] = None) -> bytes:
        """
        Descifra datos usando AES-256-GCM.
        
        Args:
            nonce: Nonce utilizado para el cifrado
            ciphertext: Datos cifrados
            associated_data: Datos adicionales autenticados
            
        Returns:
            Datos descifrados
            
        Raises:
            ValueError: Si la autenticación falla (datos manipulados)
        """
        try:
            plaintext = self.cipher.decrypt(nonce, ciphertext, associated_data)
            return plaintext
        except InvalidTag:
            # La autenticación falló - datos manipulados o clave incorrecta
            raise ValueError("Autenticación fallida: los datos pueden haber sido manipulados")
        except Exception as e:
            raise RuntimeError(f"Error al descifrar datos: {str(e)}")
    
    def encrypt_with_encoding(self, plaintext: Union[str, bytes], 
                             associated_data: Optional[Union[str, bytes]] = None) -> Dict[str, str]:
        """
        Cifra datos y devuelve el resultado codificado en base64.
        
        Args:
            plaintext: Datos a cifrar (texto o bytes)
            associated_data: Datos adicionales autenticados
            
        Returns:
            Diccionario con nonce y ciphertext codificados en base64
        """
        # Convertir a bytes si es necesario
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        if associated_data is not None and isinstance(associated_data, str):
            associated_data = associated_data.encode('utf-8')
        
        # Cifrar
        result = self.encrypt(plaintext, associated_data)
        
        # Codificar en base64
        return {
            "nonce": base64.b64encode(result["nonce"]).decode('utf-8'),
            "ciphertext": base64.b64encode(result["ciphertext"]).decode('utf-8')
        }
    
    def decrypt_from_encoding(self, nonce_b64: str, ciphertext_b64: str,
                             associated_data: Optional[Union[str, bytes]] = None) -> bytes:
        """
        Descifra datos codificados en base64.
        
        Args:
            nonce_b64: Nonce codificado en base64
            ciphertext_b64: Datos cifrados codificados en base64
            associated_data: Datos adicionales autenticados
            
        Returns:
            Datos descifrados
        """
        # Decodificar de base64
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        
        # Convertir associated_data a bytes si es necesario
        if associated_data is not None and isinstance(associated_data, str):
            associated_data = associated_data.encode('utf-8')
        
        # Descifrar
        return self.decrypt(nonce, ciphertext, associated_data)
    
    def get_key_base64(self) -> str:
        """
        Devuelve la clave actual codificada en base64.
        
        Returns:
            Clave codificada en base64
        """
        return base64.b64encode(self.key).decode('utf-8')
    
    @classmethod
    def from_base64_key(cls, key_b64: str) -> 'AESGCMCipher':
        """
        Crea una instancia con una clave codificada en base64.
        
        Args:
            key_b64: Clave codificada en base64
            
        Returns:
            Nueva instancia con la clave proporcionada
        """
        key = base64.b64decode(key_b64)
        return cls(key)
