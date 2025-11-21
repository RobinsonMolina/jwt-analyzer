import sys
from pathlib import Path
import json
from datetime import datetime, timezone, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.semantic import SemanticAnalyzer
from app.utils.base64url import base64url_encode
from app.utils.json_utils import to_json_string


def create_jwt(header: dict, payload: dict) -> str:
    """Utilidad para crear JWT de prueba"""
    header_b64 = base64url_encode(to_json_string(header).encode('utf-8'))
    payload_b64 = base64url_encode(to_json_string(payload).encode('utf-8'))
    signature = "fake_signature_for_testing"
    return f"{header_b64}.{payload_b64}.{signature}"


def test_valid_jwt_semantic():
    """Test con JWT semánticamente válido"""
    print("\n=== Test 1: JWT semánticamente válido ===")
    
    current_time = int(datetime.now(timezone.utc).timestamp())
    
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": "1234567890",
        "iss": "test-issuer",
        "aud": "test-audience",
        "iat": current_time - 100,
        "exp": current_time + 3600
    }
    
    jwt = create_jwt(header, payload)
    
    analyzer = SemanticAnalyzer()
    result = analyzer.analyze(jwt)
    
    print(f"Valid: {result['valid']}")
    print(f"Errores: {result['errors']}")
    print(f"Warnings: {result['warnings']}")
    print(f"Symbol table entries: {len(result['symbol_table'])}")
    
    assert result['valid'] == True
    assert len(result['errors']) == 0
    
    print("Test pasado!")


def test_missing_alg_field():
    """Test sin campo 'alg' obligatorio"""
    print("\n=== Test 2: Campo 'alg' faltante ===")
    
    header = {"typ": "JWT"}  # Sin 'alg'
    payload = {"sub": "1234567890"}
    
    jwt = create_jwt(header, payload)
    
    analyzer = SemanticAnalyzer()
    result = analyzer.analyze(jwt)
    
    print(f"Valid: {result['valid']}")
    print(f"Errores: {result['errors']}")
    
    assert result['valid'] == False
    assert any('alg' in error.lower() for error in result['errors'])
    
    print("Test pasado! (detectó campo faltante)")


def test_expired_token():
    """Test con token expirado"""
    print("\n=== Test 3: Token expirado ===")
    
    current_time = int(datetime.now(timezone.utc).timestamp())
    
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": "1234567890",
        "iat": current_time - 7200,
        "exp": current_time - 3600  # Expiró hace 1 hora
    }
    
    jwt = create_jwt(header, payload)
    
    analyzer = SemanticAnalyzer()
    result = analyzer.analyze(jwt)
    
    print(f"Valid: {result['valid']}")
    print(f"Errores: {result['errors']}")
    print(f"Is expired: {result['temporal_validation']['is_expired']}")
    
    assert result['valid'] == False
    assert result['temporal_validation']['is_expired'] == True
    assert any('expirado' in error.lower() for error in result['errors'])
    
    print("Test pasado! (detectó expiración)")


def test_not_yet_valid_token():
    """Test con token aún no válido (nbf)"""
    print("\n=== Test 4: Token aún no válido (nbf) ===")
    
    current_time = int(datetime.now(timezone.utc).timestamp())
    
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": "1234567890",
        "nbf": current_time + 3600,  # Válido en 1 hora
        "exp": current_time + 7200
    }
    
    jwt = create_jwt(header, payload)
    
    analyzer = SemanticAnalyzer()
    result = analyzer.analyze(jwt)
    
    print(f"Valid: {result['valid']}")
    print(f"Errores: {result['errors']}")
    print(f"Is not yet valid: {result['temporal_validation']['is_not_yet_valid']}")
    
    assert result['valid'] == False
    assert result['temporal_validation']['is_not_yet_valid'] == True
    
    print("Test pasado! (detectó nbf futuro)")


def test_wrong_type_claims():
    """Test con tipos incorrectos en claims"""
    print("\n=== Test 5: Tipos incorrectos ===")
    
    header = {"alg": 123, "typ": "JWT"}  # alg debe ser string
    payload = {
        "sub": 1234567890,  # sub debe ser string
        "exp": "not-a-number"  # exp debe ser número
    }
    
    jwt = create_jwt(header, payload)
    
    analyzer = SemanticAnalyzer()
    result = analyzer.analyze(jwt)
    
    print(f"Valid: {result['valid']}")
    print(f"Errores: {result['errors']}")
    
    assert result['valid'] == False
    assert len(result['errors']) >= 2  # Al menos 2 errores de tipo
    
    print("Test pasado! (detectó tipos incorrectos)")


def test_unsupported_algorithm():
    """Test con algoritmo no soportado"""
    print("\n=== Test 6: Algoritmo no soportado ===")
    
    header = {"alg": "HS999", "typ": "JWT"}
    payload = {"sub": "1234567890"}
    
    jwt = create_jwt(header, payload)
    
    analyzer = SemanticAnalyzer()
    result = analyzer.analyze(jwt)
    
    print(f"Valid: {result['valid']}")
    print(f"Warnings: {result['warnings']}")
    
    # Es válido pero con warning
    assert any('HS999' in warning for warning in result['warnings'])
    
    print("Test pasado! (detectó algoritmo no soportado)")


def test_symbol_table():
    """Test de la tabla de símbolos"""
    print("\n=== Test 7: Tabla de símbolos ===")
    
    header = {"alg": "HS256", "typ": "JWT", "kid": "key-123"}
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "admin": True,
        "iat": 1516239022
    }
    
    jwt = create_jwt(header, payload)
    
    analyzer = SemanticAnalyzer()
    result = analyzer.analyze(jwt)
    
    print(f"Symbol table:")
    for name, info in result['symbol_table'].items():
        print(f"  {name}: {info}")
    
    # Verificar que todos los campos estén en la tabla
    assert 'alg' in result['symbol_table']
    assert 'sub' in result['symbol_table']
    assert 'name' in result['symbol_table']
    assert 'admin' in result['symbol_table']
    
    # Verificar scopes
    assert result['symbol_table']['alg']['scope'] == 'header'
    assert result['symbol_table']['sub']['scope'] == 'payload'
    
    # Verificar tipos
    assert result['symbol_table']['admin']['type'] == 'bool'
    
    print("Test pasado!")


def test_temporal_coherence():
    """Test de coherencia temporal (nbf >= exp)"""
    print("\n=== Test 8: Incoherencia temporal ===")
    
    current_time = int(datetime.now(timezone.utc).timestamp())
    
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": "1234567890",
        "nbf": current_time + 7200,  # Válido en 2 horas
        "exp": current_time + 3600   # Expira en 1 hora (incoherente!)
    }
    
    jwt = create_jwt(header, payload)
    
    analyzer = SemanticAnalyzer()
    result = analyzer.analyze(jwt)
    
    print(f"Valid: {result['valid']}")
    print(f"Errores: {result['errors']}")
    
    assert result['valid'] == False
    assert any('incoherencia' in error.lower() for error in result['errors'])
    
    print("Test pasado! (detectó incoherencia)")


def test_no_standard_claims():
    """Test sin claims estándar"""
    print("\n=== Test 9: Sin claims estándar ===")
    
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "custom_field_1": "value1",
        "custom_field_2": 123
    }
    
    jwt = create_jwt(header, payload)
    
    analyzer = SemanticAnalyzer()
    result = analyzer.analyze(jwt)
    
    print(f"Valid: {result['valid']}")
    print(f"Warnings: {result['warnings']}")
    
    assert any('claim estándar' in warning.lower() for warning in result['warnings'])
    
    print("Test pasado! (detectó falta de claims estándar)")


def test_summaries():
    """Test de resúmenes de validación"""
    print("\n=== Test 10: Resúmenes ===")
    
    header = {"alg": "HS256", "typ": "JWT", "custom_header": "value"}
    payload = {
        "sub": "1234567890",
        "iss": "test",
        "custom_claim": "value"
    }
    
    jwt = create_jwt(header, payload)
    
    analyzer = SemanticAnalyzer()
    result = analyzer.analyze(jwt)
    
    print(f"Header summary: {result['header_validation']}")
    print(f"Payload summary: {result['payload_validation']}")
    
    assert result['header_validation']['fields_count'] == 3
    assert 'alg' in result['header_validation']['standard_fields']
    assert 'custom_header' in result['header_validation']['custom_fields']
    
    assert result['payload_validation']['claims_count'] == 3
    assert 'sub' in result['payload_validation']['standard_claims']
    assert 'custom_claim' in result['payload_validation']['custom_claims']
    
    print("Test pasado!")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("EJECUTANDO TESTS DEL ANALIZADOR SEMÁNTICO")
    print("="*60)
    
    test_valid_jwt_semantic()
    test_missing_alg_field()
    test_expired_token()
    test_not_yet_valid_token()
    test_wrong_type_claims()
    test_unsupported_algorithm()
    test_symbol_table()
    test_temporal_coherence()
    test_no_standard_claims()
    test_summaries()
    
    print("\n" + "="*60)
    print("¡TODOS LOS TESTS DEL ANALIZADOR SEMÁNTICO PASARON!")
    print("="*60)