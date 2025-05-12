"""
Rutas de la API para contenido educativo sobre criptografía post-cuántica.

Este módulo proporciona endpoints para acceder a información educativa
sobre criptografía post-cuántica, especialmente CRYSTALS-Kyber.
"""
from fastapi import APIRouter, HTTPException
from typing import Dict, Any

from app.crypto.kyber import KyberManager
from app.models.schemas import EducationalContent

router = APIRouter()

@router.get("/quantum-crypto", response_model=EducationalContent)
async def get_quantum_crypto_info():
    """
    Proporciona información educativa sobre criptografía post-cuántica.
    
    Returns:
        Contenido educativo sobre criptografía post-cuántica
    """
    return {
        "title": "Criptografía Post-Cuántica",
        "description": "La criptografía post-cuántica se refiere a algoritmos criptográficos diseñados para resistir ataques de computadoras cuánticas. Los algoritmos tradicionales como RSA y ECC son vulnerables ante computadoras cuánticas debido al algoritmo de Shor, que puede factorizar eficientemente números grandes.",
        "sections": [
            {
                "title": "CRYSTALS-Kyber",
                "content": "CRYSTALS-Kyber es un mecanismo de encapsulamiento de claves (KEM) basado en problemas de retículos. Ha sido seleccionado por el NIST como el primer estándar para criptografía post-cuántica. Su seguridad se basa en la dificultad del problema 'Learning With Errors' (LWE)."
            },
            {
                "title": "Comparación con RSA/ECC",
                "content": "Mientras que RSA basa su seguridad en la factorización de números grandes y ECC en el problema del logaritmo discreto en curvas elípticas, Kyber utiliza estructuras matemáticas llamadas retículos que son resistentes a ataques cuánticos conocidos."
            },
            {
                "title": "Niveles de Seguridad",
                "content": "Kyber ofrece tres variantes con diferentes niveles de seguridad: Kyber512, Kyber768 y Kyber1024. Estos números representan el tamaño de los parámetros, y ofrecen distintos equilibrios entre seguridad y rendimiento."
            },
            {
                "title": "Funcionamiento Básico",
                "content": "En un intercambio de claves Kyber, una parte genera una clave pública y privada. La otra parte usa la clave pública para encapsular una clave compartida secreta, generando un ciphertext. La primera parte puede desencapsular este ciphertext usando su clave privada para obtener la misma clave compartida."
            }
        ],
        "additional_resources": [
            {
                "title": "Sitio web oficial de CRYSTALS-Kyber",
                "url": "https://pq-crystals.org/kyber/"
            },
            {
                "title": "Estandarización NIST de Criptografía Post-Cuántica",
                "url": "https://csrc.nist.gov/projects/post-quantum-cryptography"
            }
        ]
    }

@router.get("/kyber-details")
async def get_kyber_technical_details():
    """
    Proporciona detalles técnicos sobre el algoritmo CRYSTALS-Kyber.
    
    Returns:
        Detalles técnicos del algoritmo Kyber
    """
    try:
        # Obtener información técnica del algoritmo
        details = KyberManager.get_algorithm_details()
        
        # Agregar explicaciones educativas
        details["explanation"] = {
            "claimed_nist_level": "Nivel de seguridad según categorías del NIST. Un nivel más alto indica mayor seguridad.",
            "public_key_length": "Tamaño de la clave pública en bytes. Impacta en el ancho de banda necesario para transmitirla.",
            "secret_key_length": "Tamaño de la clave privada en bytes. Determina el almacenamiento necesario para guardarla.",
            "ciphertext_length": "Tamaño del texto cifrado (ciphertext) en bytes. Afecta al overhead de comunicación.",
            "shared_key_length": "Tamaño de la clave compartida resultante en bytes. Esta clave se usa para cifrado simétrico."
        }
        
        return details
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener detalles de Kyber: {str(e)}")

@router.get("/aes-gcm")
async def get_aes_gcm_info():
    """
    Proporciona información educativa sobre AES-256-GCM.
    
    Returns:
        Contenido educativo sobre AES-256-GCM
    """
    return {
        "title": "AES-256-GCM",
        "description": "AES-256-GCM es un modo de cifrado simétrico que proporciona confidencialidad y autenticación simultáneamente. Es ampliamente utilizado en protocolos de seguridad modernos.",
        "sections": [
            {
                "title": "Algoritmo AES",
                "content": "Advanced Encryption Standard (AES) es un algoritmo de cifrado por bloques adoptado como estándar por el NIST en 2001. AES-256 utiliza claves de 256 bits, lo que proporciona un nivel de seguridad extremadamente alto."
            },
            {
                "title": "Modo GCM",
                "content": "Galois/Counter Mode (GCM) es un modo de operación para cifrados de bloque. Proporciona cifrado autenticado con datos asociados (AEAD), lo que significa que garantiza tanto confidencialidad como integridad y autenticidad."
            },
            {
                "title": "Seguridad Cuántica",
                "content": "AES-256 se considera resistente a ataques cuánticos si se implementa correctamente. El algoritmo de Grover podría reducir teóricamente la seguridad de AES-256 a aproximadamente 128 bits en una computadora cuántica, pero esto sigue siendo suficiente para la mayoría de las aplicaciones."
            },
            {
                "title": "Ventajas",
                "content": "AES-GCM ofrece excelente rendimiento, tanto en hardware como en software. La combinación de cifrado y autenticación en un solo paso lo hace eficiente para aplicaciones como VPNs donde se procesan grandes volúmenes de datos."
            }
        ]
    }
