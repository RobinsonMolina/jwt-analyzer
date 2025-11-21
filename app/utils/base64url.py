"""
Utilidades para codificación y decodificación Base64URL
Base64URL es como Base64 pero seguro para URLs:
- Reemplaza + por -
- Reemplaza / por _
- No usa padding (=)
"""
import base64
from app.utils.errors import DecodingError, EncodingError


def is_valid_base64url_char(char: str) -> bool:
    """
    Verifica si un caracter es válido en Base64URL
    Alfabeto: A-Z, a-z, 0-9, -, _
    """
    return char.isalnum() or char in ['-', '_']


def is_valid_base64url(string: str) -> bool:
    """
    Verifica si una cadena es Base64URL válida
    """
    if not string:
        return False
    
    # Verificar que todos los caracteres sean válidos
    return all(is_valid_base64url_char(c) for c in string)


def base64url_decode(encoded: str) -> bytes:
    """
    Decodifica una cadena Base64URL a bytes
    
    Args:
        encoded: Cadena codificada en Base64URL
        
    Returns:
        bytes: Datos decodificados
        
    Raises:
        DecodingError: Si la cadena no es Base64URL válido
    """
    if not encoded:
        raise DecodingError("La cadena a decodificar está vacía")
    
    # Verificar caracteres válidos
    if not is_valid_base64url(encoded):
        invalid_chars = [c for c in encoded if not is_valid_base64url_char(c)]
        raise DecodingError(
            f"Caracteres inválidos en Base64URL: {set(invalid_chars)}"
        )
    
    try:
        # Convertir Base64URL a Base64 estándar
        # Reemplazar caracteres específicos de URL
        standard_base64 = encoded.replace('-', '+').replace('_', '/')
        
        # Agregar padding si es necesario
        # Base64 requiere que la longitud sea múltiplo de 4
        padding = 4 - (len(standard_base64) % 4)
        if padding != 4:
            standard_base64 += '=' * padding
        
        # Decodificar
        decoded = base64.b64decode(standard_base64)
        return decoded
        
    except Exception as e:
        raise DecodingError(f"Error al decodificar Base64URL: {str(e)}")


def base64url_encode(data: bytes) -> str:
    """
    Codifica bytes a Base64URL
    
    Args:
        data: Bytes a codificar
        
    Returns:
        str: Cadena codificada en Base64URL
        
    Raises:
        EncodingError: Si hay error en la codificación
    """
    if not isinstance(data, bytes):
        raise EncodingError("Los datos deben ser de tipo bytes")
    
    try:
        # Codificar a Base64 estándar
        encoded = base64.b64encode(data).decode('utf-8')
        
        # Convertir a Base64URL
        # Reemplazar caracteres y quitar padding
        base64url = encoded.replace('+', '-').replace('/', '_').rstrip('=')
        
        return base64url
        
    except Exception as e:
        raise EncodingError(f"Error al codificar Base64URL: {str(e)}")