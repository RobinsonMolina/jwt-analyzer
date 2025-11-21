import sys
from pathlib import Path
import json

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.jwt_decoder import JWTDecoder


def test_decode_valid_jwt():
    """Test de decodificación exitosa"""
    print("\n=== Test 1: Decodificar JWT válido ===")
    
    # JWT de ejemplo: header={"alg":"HS256","typ":"JWT"}, payload={"sub":"1234567890"}
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    
    decoder = JWTDecoder()
    result = decoder.decode(jwt)
    
    print(f"Valid: {result['valid']}")
    print(f"Header: {result['header']}")
    print(f"Payload: {result['payload']}")
    print(f"Signature: {result['signature']}")
    
    assert result['valid'] == True
    assert result['header']['alg'] == 'HS256'
    assert result['header']['typ'] == 'JWT'
    assert result['payload']['sub'] == '1234567890'
    
    print("Test pasado!")


def test_decode_header_only():
    """Test de decodificación de header solamente"""
    print("\n=== Test 2: Decodificar solo header ===")
    
    header_b64 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    
    decoder = JWTDecoder()
    result = decoder.decode_part(header_b64, "header")
    
    print(f"Valid: {result['valid']}")
    print(f"Data: {result['data']}")
    
    assert result['valid'] == True
    assert result['data']['alg'] == 'HS256'
    
    print("Test pasado!")


def test_decode_payload_only():
    """Test de decodificación de payload solamente"""
    print("\n=== Test 3: Decodificar solo payload ===")
    
    payload_b64 = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    
    decoder = JWTDecoder()
    result = decoder.decode_part(payload_b64, "payload")
    
    print(f"Valid: {result['valid']}")
    print(f"Data: {result['data']}")
    
    assert result['valid'] == True
    assert result['data']['sub'] == '1234567890'
    assert result['data']['name'] == 'John Doe'
    assert result['data']['iat'] == 1516239022
    
    print("Test pasado!")


def test_extract_claims():
    """Test de extracción de claims"""
    print("\n=== Test 4: Extraer claims ===")
    
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    decoder = JWTDecoder()
    result = decoder.decode(jwt)
    
    claims = decoder.extract_claims(result['payload'])
    
    print(f"Standard claims: {list(claims['standard'].keys())}")
    print(f"Custom claims: {list(claims['custom'].keys())}")
    
    assert 'sub' in claims['standard']
    assert 'iat' in claims['standard']
    assert 'name' in claims['custom']
    
    print("Test pasado!")


def test_visualize():
    """Test de visualización"""
    print("\n=== Test 5: Visualizar JWT ===")
    
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A"
    
    decoder = JWTDecoder()
    result = decoder.decode(jwt)
    
    visualization = decoder.visualize(result)
    
    print(visualization)
    
    assert "HEADER" in visualization
    assert "PAYLOAD" in visualization
    assert "SIGNATURE" in visualization
    
    print("Test pasado!")


def test_decode_invalid_base64():
    """Test con Base64URL inválido"""
    print("\n=== Test 6: Base64URL inválido ===")
    
    jwt = "invalid+base64.invalid/base64.signature"
    
    decoder = JWTDecoder()
    result = decoder.decode(jwt)
    
    print(f"Valid: {result['valid']}")
    print(f"Errors: {result['errors']}")
    
    assert result['valid'] == False
    assert len(result['errors']) > 0
    
    print("Test pasado! (detectó Base64URL inválido)")


def test_decode_invalid_json():
    """Test con JSON inválido"""
    print("\n=== Test 7: JSON inválido ===")
    
    # "invalid" en Base64URL = aW52YWxpZA
    jwt = "aW52YWxpZA.aW52YWxpZA.signature"
    
    decoder = JWTDecoder()
    result = decoder.decode(jwt)
    
    print(f"Valid: {result['valid']}")
    print(f"Errors: {result['errors']}")
    
    assert result['valid'] == False
    
    print("Test pasado! (detectó JSON inválido)")


def test_decode_missing_fields():
    """Test con campos faltantes en header"""
    print("\n=== Test 8: Campos faltantes ===")
    
    # Header sin 'typ': {"alg":"HS256"}
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
    
    decoder = JWTDecoder()
    result = decoder.decode(jwt)
    
    print(f"Valid: {result['valid']}")
    print(f"Warnings: {result['warnings']}")
    
    # Debe decodificar pero con warning
    assert result['valid'] == True
    assert len(result['warnings']) > 0
    
    print("Test pasado! (detectó campo faltante)")


def test_raw_parts():
    """Test de partes raw"""
    print("\n=== Test 9: Partes raw ===")
    
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    
    decoder = JWTDecoder()
    result = decoder.decode(jwt)
    
    print(f"Raw header: {result['raw']['header']}")
    print(f"Raw payload: {result['raw']['payload']}")
    print(f"Raw signature: {result['raw']['signature']}")
    
    assert result['raw']['header'] == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    assert result['raw']['payload'] == "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    assert result['raw']['signature'] == "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    
    print("Test pasado!")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("EJECUTANDO TESTS DEL DECODER")
    print("="*60)
    
    test_decode_valid_jwt()
    test_decode_header_only()
    test_decode_payload_only()
    test_extract_claims()
    test_visualize()
    test_decode_invalid_base64()
    test_decode_invalid_json()
    test_decode_missing_fields()
    test_raw_parts()
    
    print("\n" + "="*60)
    print("¡TODOS LOS TESTS DEL DECODER PASARON!")
    print("="*60)