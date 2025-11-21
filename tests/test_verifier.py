import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.jwt_encoder import JWTEncoder
from app.services.verifier import JWTVerifier


def test_verify_valid_signature():
    """Test de verificación exitosa"""
    print("\n=== Test 1: Verificar firma válida ===")
    
    # Crear un JWT
    payload = {"sub": "1234567890", "name": "John Doe"}
    secret = "my-secret-key"
    
    encoder = JWTEncoder()
    encoded = encoder.encode(payload, secret)
    
    # Verificar
    verifier = JWTVerifier()
    result = verifier.verify(encoded['token'], secret)
    
    print(f"Valid: {result['valid']}")
    print(f"Signature match: {result['signature_match']}")
    print(f"Algorithm: {result['algorithm']}")
    
    assert result['valid'] == True
    assert result['signature_match'] == True
    assert len(result['errors']) == 0
    
    print("Test pasado!")


def test_verify_invalid_signature():
    """Test con firma inválida (token manipulado)"""
    print("\n=== Test 2: Verificar firma inválida ===")
    
    # Crear un JWT
    payload = {"sub": "1234567890"}
    secret = "original-secret"
    
    encoder = JWTEncoder()
    encoded = encoder.encode(payload, secret)
    
    # Modificar el token (manipulación)
    tampered_token = encoded['token'][:-5] + "xxxxx"
    
    # Verificar con secret correcto
    verifier = JWTVerifier()
    result = verifier.verify(tampered_token, secret)
    
    print(f"Valid: {result['valid']}")
    print(f"Signature match: {result['signature_match']}")
    print(f"Errors: {result['errors']}")
    
    assert result['valid'] == False
    assert result['signature_match'] == False
    assert len(result['errors']) > 0

    print("Test pasado! (detectó manipulación)")


def test_verify_wrong_secret():
    """Test con secret incorrecto"""
    print("\n=== Test 3: Secret incorrecto ===")
    
    # Crear JWT con un secret
    payload = {"sub": "test"}
    correct_secret = "correct-secret"
    wrong_secret = "wrong-secret"
    
    encoder = JWTEncoder()
    encoded = encoder.encode(payload, correct_secret)
    
    # Verificar con secret incorrecto
    verifier = JWTVerifier()
    result = verifier.verify(encoded['token'], wrong_secret)
    
    print(f"Valid: {result['valid']}")
    print(f"Errors: {result['errors']}")
    
    assert result['valid'] == False
    assert result['signature_match'] == False
    
    print("Test pasado! (detectó secret incorrecto)")


def test_verify_different_algorithms():
    """Test con diferentes algoritmos"""
    print("\n=== Test 4: Diferentes algoritmos ===")
    
    payload = {"sub": "test"}
    secret = "secret"
    algorithms = ['HS256', 'HS384', 'HS512']
    
    for alg in algorithms:
        # Codificar
        encoder = JWTEncoder()
        encoded = encoder.encode(payload, secret, algorithm=alg)
        
        # Verificar
        verifier = JWTVerifier()
        result = verifier.verify(encoded['token'], secret)
        
        print(f"{alg}: Valid={result['valid']}, Match={result['signature_match']}")
        
        assert result['valid'] == True
        assert result['algorithm'] == alg
    
    print("Test pasado!")


def test_verify_none_algorithm():
    """Test con token sin firma (none)"""
    print("\n=== Test 5: Token sin firma (none) ===")
    
    payload = {"sub": "test"}
    
    encoder = JWTEncoder()
    encoded = encoder.create_token_without_signature(payload)
    
    print(f"Token generado: {encoded['token']}")
    
    # Verificar
    verifier = JWTVerifier()
    result = verifier.verify(encoded['token'], "any-secret")
    
    print(f"Valid: {result['valid']}")
    print(f"Algorithm: {result['algorithm']}")
    print(f"Warnings: {result['warnings']}")
    
    # Para algoritmo 'none', debería ser válido pero con warnings
    if result['algorithm']:
        assert result['algorithm'] == 'none'
    assert len(result['warnings']) > 0  # Debe tener warnings
    
    print("Test pasado! (detectó none)")


def test_verify_and_decode():
    """Test de verificar y decodificar juntos"""
    print("\n=== Test 6: Verificar y decodificar ===")
    
    payload = {"sub": "user123", "role": "admin"}
    secret = "secret"
    
    # Codificar
    encoder = JWTEncoder()
    encoded = encoder.encode(payload, secret)
    
    # Verificar y decodificar
    verifier = JWTVerifier()
    result = verifier.verify_and_decode(encoded['token'], secret)
    
    print(f"Valid: {result['valid']}")
    print(f"Verified: {result['verified']}")
    print(f"Decoded payload: {result['decoded']['payload']}")
    
    assert result['valid'] == True
    assert result['verified'] == True
    assert result['decoded']['payload']['sub'] == 'user123'
    
    print("Test pasado!")


def test_detect_tampering():
    """Test de detección de manipulación"""
    print("\n=== Test 7: Detectar manipulación ===")
    
    payload = {"sub": "test", "data": "original"}
    secret = "secret"
    
    # Crear JWT original
    encoder = JWTEncoder()
    encoded = encoder.encode(payload, secret)
    
    # Manipular el token
    parts = encoded['token'].split('.')
    # Cambiar un carácter del payload
    tampered_payload = parts[1][:-1] + 'X'
    tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"
    
    # Detectar manipulación
    verifier = JWTVerifier()
    result = verifier.detect_tampering(tampered_token, secret)
    
    print(f"Is tampered: {result['is_tampered']}")
    print(f"Indicators: {result['tampering_indicators']}")
    
    assert result['is_tampered'] == True
    assert len(result['tampering_indicators']) > 0
    
    print("Test pasado! (detectó manipulación)")


def test_verify_with_multiple_secrets():
    """Test con múltiples secrets (rotación de claves)"""
    print("\n=== Test 8: Múltiples secrets ===")
    
    payload = {"sub": "test"}
    correct_secret = "secret-2"
    secrets = ["secret-1", "secret-2", "secret-3"]
    
    # Crear JWT con secret-2
    encoder = JWTEncoder()
    encoded = encoder.encode(payload, correct_secret)
    
    # Verificar con lista de secrets
    verifier = JWTVerifier()
    result = verifier.verify_with_multiple_secrets(encoded['token'], secrets)
    
    print(f"Valid: {result['valid']}")
    print(f"Matched secret index: {result['matched_secret_index']}")
    
    assert result['valid'] == True
    assert result['matched_secret_index'] == 1  # secret-2 está en índice 1
    
    print("Test pasado!")


def test_signature_consistency():
    """Test de consistencia de verificación"""
    print("\n=== Test 9: Consistencia de verificación ===")
    
    payload = {"sub": "test"}
    secret = "secret"
    
    # Crear JWT
    encoder = JWTEncoder()
    encoded = encoder.encode(payload, secret)
    
    # Verificar múltiples veces
    verifier = JWTVerifier()
    
    for i in range(3):
        result = verifier.verify(encoded['token'], secret)
        assert result['valid'] == True
        print(f"Verificación {i+1}:")
    
    print("Test pasado! (verificación consistente)")


def test_actual_vs_expected_signature():
    """Test de firmas esperada vs actual"""
    print("\n=== Test 10: Firmas esperada vs actual ===")
    
    payload = {"sub": "test"}
    secret = "secret"
    
    # Crear JWT
    encoder = JWTEncoder()
    encoded = encoder.encode(payload, secret)
    
    # Verificar
    verifier = JWTVerifier()
    result = verifier.verify(encoded['token'], secret)
    
    print(f"Expected signature: {result['expected_signature']}")
    print(f"Actual signature:   {result['actual_signature']}")
    print(f"Match: {result['expected_signature'] == result['actual_signature']}")
    
    assert result['expected_signature'] == result['actual_signature']
    
    print("Test pasado!")


def test_complete_flow():
    """Test del flujo completo: encode -> verify -> decode"""
    print("\n=== Test 11: Flujo completo ===")
    
    # 1. Crear payload
    original_payload = {
        "sub": "user123",
        "name": "Test User",
        "role": "admin",
        "permissions": ["read", "write"]
    }
    secret = "super-secret-key"
    
    # 2. Codificar
    encoder = JWTEncoder()
    encoded = encoder.encode(original_payload, secret, algorithm='HS256')
    token = encoded['token']
    
    print(f"Token generado: {token[:50]}...")
    
    # 3. Verificar
    verifier = JWTVerifier()
    verification = verifier.verify(token, secret)
    
    print(f"Firma válida: {verification['valid']}")
    assert verification['valid'] == True
    
    # 4. Decodificar
    decoded_payload = verification['decoded']['payload']
    
    print(f"Payload decodificado: {decoded_payload}")
    
    # 5. Verificar que el payload coincida
    assert decoded_payload['sub'] == original_payload['sub']
    assert decoded_payload['name'] == original_payload['name']
    assert decoded_payload['role'] == original_payload['role']
    
    print("Test pasado! (flujo completo exitoso)")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("EJECUTANDO TESTS DEL VERIFIER")
    print("="*60)
    
    test_verify_valid_signature()
    test_verify_invalid_signature()
    test_verify_wrong_secret()
    test_verify_different_algorithms()
    test_verify_none_algorithm()
    test_verify_and_decode()
    test_detect_tampering()
    test_verify_with_multiple_secrets()
    test_signature_consistency()
    test_actual_vs_expected_signature()
    test_complete_flow()
    
    print("\n" + "="*60)
    print("¡TODOS LOS TESTS DEL VERIFIER PASARON!")
    print("="*60)