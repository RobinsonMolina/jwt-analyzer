import sys
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.jwt_encoder import JWTEncoder
from app.services.jwt_decoder import JWTDecoder


def test_encode_simple_jwt():
    """Test de codificación básica"""
    print("\n=== Test 1: Codificar JWT simple ===")
    
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "admin": True
    }
    secret = "my-secret-key"
    
    encoder = JWTEncoder()
    result = encoder.encode(payload, secret)
    
    print(f"Valid: {result['valid']}")
    print(f"Token: {result['token']}")
    print(f"Algorithm: {result['algorithm']}")
    
    assert result['valid'] == True
    assert result['token'] is not None
    assert '.' in result['token']
    assert result['token'].count('.') == 2  # header.payload.signature
    
    print("Test pasado!")


def test_encode_and_decode():
    """Test de codificar y luego decodificar"""
    print("\n=== Test 2: Codificar y decodificar ===")
    
    payload = {
        "sub": "user123",
        "email": "user@example.com",
        "role": "admin"
    }
    secret = "test-secret"
    
    # Codificar
    encoder = JWTEncoder()
    encoded = encoder.encode(payload, secret)
    
    print(f"JWT generado: {encoded['token'][:50]}...")
    
    # Decodificar
    decoder = JWTDecoder()
    decoded = decoder.decode(encoded['token'])
    
    print(f"Payload decodificado: {decoded['payload']}")
    
    # Verificar que el payload coincida
    assert decoded['valid'] == True
    assert decoded['payload']['sub'] == payload['sub']
    assert decoded['payload']['email'] == payload['email']
    assert decoded['payload']['role'] == payload['role']
    
    print("Test pasado!")


def test_encode_with_expiration():
    """Test con tiempo de expiración"""
    print("\n=== Test 3: JWT con expiración ===")
    
    payload = {"sub": "1234567890"}
    secret = "my-secret"
    
    encoder = JWTEncoder()
    result = encoder.create_token_with_expiration(
        payload, 
        secret, 
        expires_in_seconds=3600  # 1 hora
    )
    
    print(f"Token generado: {result['token'][:50]}...")
    print(f"Payload: {result['decoded']['payload']}")
    
    assert result['valid'] == True
    assert 'iat' in result['decoded']['payload']
    assert 'exp' in result['decoded']['payload']
    
    # Verificar que exp sea mayor que iat
    iat = result['decoded']['payload']['iat']
    exp = result['decoded']['payload']['exp']
    assert exp > iat
    assert exp - iat == 3600
    
    print("Test pasado!")


def test_different_algorithms():
    """Test con diferentes algoritmos"""
    print("\n=== Test 4: Diferentes algoritmos ===")
    
    payload = {"sub": "test"}
    secret = "secret"
    
    algorithms = ['HS256', 'HS384', 'HS512']
    
    for alg in algorithms:
        encoder = JWTEncoder()
        result = encoder.encode(payload, secret, algorithm=alg)
        
        print(f"{alg}: {result['token'][:50]}...")
        
        assert result['valid'] == True
        assert result['algorithm'] == alg
        assert result['decoded']['header']['alg'] == alg
    
    print("Test pasado!")


def test_custom_header():
    """Test con header personalizado"""
    print("\n=== Test 5: Header personalizado ===")
    
    custom_header = {
        "alg": "HS256",
        "typ": "JWT",
        "kid": "key-123"
    }
    payload = {"sub": "1234567890"}
    secret = "secret"
    
    encoder = JWTEncoder()
    result = encoder.encode(payload, secret, header=custom_header)
    
    print(f"Header: {result['decoded']['header']}")
    
    assert result['valid'] == True
    assert result['decoded']['header']['kid'] == "key-123"
    
    print("Test pasado!")


def test_unsupported_algorithm():
    """Test con algoritmo no soportado"""
    print("\n=== Test 6: Algoritmo no soportado ===")
    
    payload = {"sub": "test"}
    secret = "secret"
    
    encoder = JWTEncoder()
    result = encoder.encode(payload, secret, algorithm='RS256')
    
    print(f"Valid: {result['valid']}")
    print(f"Errors: {result['errors']}")
    
    assert result['valid'] == False
    assert len(result['errors']) > 0
    
    print("Test pasado! (detectó algoritmo no soportado)")


def test_empty_secret():
    """Test con secret vacío"""
    print("\n=== Test 7: Secret vacío ===")
    
    payload = {"sub": "test"}
    secret = ""
    
    encoder = JWTEncoder()
    result = encoder.encode(payload, secret)
    
    print(f"Valid: {result['valid']}")
    print(f"Errors: {result['errors']}")
    
    assert result['valid'] == False
    assert any('secreta' in error.lower() for error in result['errors'])
    
    print("Test pasado! (detectó secret vacío)")


def test_invalid_payload_types():
    """Test con tipos inválidos en payload"""
    print("\n=== Test 8: Tipos inválidos ===")
    
    payload = {
        "sub": "test",
        "exp": "not-a-number"  # Debe ser número
    }
    secret = "secret"
    
    encoder = JWTEncoder()
    result = encoder.encode(payload, secret)
    
    print(f"Valid: {result['valid']}")
    print(f"Errors: {result['errors']}")
    
    assert result['valid'] == False
    
    print("Test pasado! (detectó tipo inválido)")


def test_empty_payload():
    """Test con payload vacío"""
    print("\n=== Test 9: Payload vacío ===")
    
    payload = {}
    secret = "secret"
    
    encoder = JWTEncoder()
    result = encoder.encode(payload, secret)
    
    print(f"Valid: {result['valid']}")
    print(f"Warnings: {result['warnings']}")
    
    # Es válido pero con warnings
    assert result['valid'] == True
    assert len(result['warnings']) > 0
    
    print("Test pasado! (payload vacío con warning)")


def test_token_without_signature():
    """Test de token sin firma (inseguro)"""
    print("\n=== Test 10: Token sin firma (none) ===")
    
    payload = {"sub": "test", "name": "Test User"}
    
    encoder = JWTEncoder()
    result = encoder.create_token_without_signature(payload)
    
    print(f"Token: {result['token']}")
    print(f"Warnings: {result['warnings']}")
    
    assert result['valid'] == True
    assert result['token'].endswith('.')  # Sin firma termina en '.'
    assert result['algorithm'] == 'none'
    assert len(result['warnings']) > 0  # Debe tener warning de inseguridad
    
    print("Test pasado!")


def test_jwt_parts():
    """Test de las partes individuales del JWT"""
    print("\n=== Test 11: Partes del JWT ===")
    
    payload = {"sub": "test"}
    secret = "secret"
    
    encoder = JWTEncoder()
    result = encoder.encode(payload, secret)
    
    parts = result['parts']
    
    print(f"Header: {parts['header']}")
    print(f"Payload: {parts['payload']}")
    print(f"Signature: {parts['signature']}")
    
    # Verificar que todas las partes existan
    assert parts['header']
    assert parts['payload']
    assert parts['signature']
    
    # Verificar que el token se pueda reconstruir
    reconstructed = f"{parts['header']}.{parts['payload']}.{parts['signature']}"
    assert reconstructed == result['token']
    
    print("Test pasado!")


def test_signature_consistency():
    """Test de consistencia de firma"""
    print("\n=== Test 12: Consistencia de firma ===")
    
    payload = {"sub": "test", "data": "value"}
    secret = "my-secret"
    
    encoder = JWTEncoder()
    
    # Generar el mismo JWT dos veces
    result1 = encoder.encode(payload, secret)
    result2 = encoder.encode(payload, secret)
    
    print(f"Token 1: {result1['token'][:50]}...")
    print(f"Token 2: {result2['token'][:50]}...")
    
    # Las firmas deben ser idénticas
    assert result1['parts']['signature'] == result2['parts']['signature']
    
    print("Test pasado! (firmas consistentes)")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("EJECUTANDO TESTS DEL ENCODER")
    print("="*60)
    
    test_encode_simple_jwt()
    test_encode_and_decode()
    test_encode_with_expiration()
    test_different_algorithms()
    test_custom_header()
    test_unsupported_algorithm()
    test_empty_secret()
    test_invalid_payload_types()
    test_empty_payload()
    test_token_without_signature()
    test_jwt_parts()
    test_signature_consistency()
    
    print("\n" + "="*60)
    print("¡TODOS LOS TESTS DEL ENCODER PASARON!")
    print("="*60)