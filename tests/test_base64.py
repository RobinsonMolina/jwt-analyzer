import sys
from pathlib import Path

# Agregar el directorio padre al path para poder importar 'app'
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.utils.base64url import base64url_encode, base64url_decode, is_valid_base64url


def test_encode_decode():
    """Prueba codificación y decodificación"""
    print("\n=== Test 1: Encode/Decode ===")
    data = b"Hello JWT Robin"
    encoded = base64url_encode(data)
    decoded = base64url_decode(encoded)
    
    print(f"Original: {data}")
    print(f"Encoded: {encoded}")
    print(f"Decoded: {decoded}")
    print(f"Match: {data == decoded}")
    
    assert data == decoded, "Los datos no coinciden"
    print("Test pasado!")


def test_valid_base64url():
    """Prueba validación de caracteres"""
    print("\n=== Test 2: Validación de caracteres ===")
    
    # Válidos
    valid = "abc-def_123"
    print(f"'{valid}' es válido: {is_valid_base64url(valid)}")
    assert is_valid_base64url(valid) == True
    
    # Inválidos (+ y / son de Base64 estándar, no Base64URL)
    invalid = "abc+def/"
    print(f"'{invalid}' es válido: {is_valid_base64url(invalid)}")
    assert is_valid_base64url(invalid) == False
    
    print("Test pasado!")


def test_jwt_real():
    """Prueba con partes de JWT real"""
    print("\n=== Test 3: JWT Real ===")
    
    # Header de JWT: {"alg":"HS256","typ":"JWT"}
    header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    decoded_header = base64url_decode(header).decode('utf-8')
    print(f"Header: {decoded_header}")
    
    # Payload de JWT: {"sub":"1234567890"}
    payload = "eyJzdWIiOiIxMjM0NTY3ODkwIn0/"
    decoded_payload = base64url_decode(payload).decode('utf-8')
    print(f"Payload: {decoded_payload}")
    
    assert '{"alg":"HS256","typ":"JWT"}' == decoded_header
    assert '{"sub":"1234567890"}' == decoded_payload
    
    print("Test pasado!")


if __name__ == "__main__":
    test_encode_decode()
    test_valid_base64url()
    test_jwt_real()
    print("\n¡Todos los tests pasaron!")