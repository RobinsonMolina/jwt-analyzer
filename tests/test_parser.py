import sys
from pathlib import Path
import json

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.parser import JWTParser


def test_valid_jwt_syntax():
    """Test con JWT sintácticamente correcto"""
    print("\n=== Test 1: JWT sintácticamente válido ===")
    
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    
    parser = JWTParser()
    result = parser.parse(jwt)
    
    print(f"Valid: {result['valid']}")
    print(f"Errores: {result['errors']}")
    print(f"Warnings: {result['warnings']}")
    
    assert result['valid'] == True
    assert len(result['errors']) == 0
    assert result['derivation_tree'] is not None
    
    print("Test pasado!")


def test_jwt_missing_parts():
    """Test con JWT incompleto (falta signature)"""
    print("\n=== Test 2: JWT incompleto ===")
    
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    
    parser = JWTParser()
    result = parser.parse(jwt)
    
    print(f"Valid: {result['valid']}")
    print(f"Errores: {result['errors']}")
    
    assert result['valid'] == False
    assert len(result['errors']) > 0
    
    print("Test pasado! (detectó estructura incompleta)")


def test_jwt_invalid_characters():
    """Test con caracteres inválidos en la sintaxis"""
    print("\n=== Test 3: JWT con caracteres inválidos ===")
    
    jwt = "eyJhbGc+OiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjg+ryP4J3jVmNHl0w5N/XgL0n3I9PlFUP0THsR8U"
    
    parser = JWTParser()
    result = parser.parse(jwt)
    
    print(f"Valid: {result['valid']}")
    print(f"Errores: {result['errors']}")
    
    # Debe fallar en análisis léxico
    assert result['valid'] == False
    assert result['lexical_analysis']['valid'] == False
    
    print("Test pasado! (detectó caracteres inválidos)")


def test_jwt_too_many_parts():
    """Test con más de 3 partes"""
    print("\n=== Test 4: JWT con partes adicionales ===")
    
    jwt = "header.payload.signature.extra"
    
    parser = JWTParser()
    result = parser.parse(jwt)
    
    print(f"Valid: {result['valid']}")
    print(f"Errores: {result['errors']}")
    
    assert result['valid'] == False
    
    print("Test pasado! (detectó partes adicionales)")


def test_derivation_tree():
    """Test del árbol de derivación"""
    print("\n=== Test 5: Árbol de derivación ===")
    
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    
    parser = JWTParser()
    result = parser.parse(jwt)
    
    print("Árbol de derivación:")
    print(json.dumps(result['derivation_tree'], indent=2))
    
    assert result['derivation_tree'] is not None
    assert 'rule' in result['derivation_tree']
    assert 'children' in result['derivation_tree']
    assert len(result['derivation_tree']['children']) == 5  # 3 partes + 2 delimitadores
    
    print("Test pasado!")


def test_derivation_steps():
    """Test de los pasos de derivación"""
    print("\n=== Test 6: Pasos de derivación ===")
    
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    
    parser = JWTParser()
    result = parser.parse(jwt)
    
    steps = parser.get_derivation_steps()
    
    print("Pasos de derivación:")
    for step in steps:
        print(f"  {step}")
    
    assert len(steps) > 0
    assert "JWT" in steps[0]
    
    print("Test pasado!")


def test_grammar_information():
    """Test de información de la gramática"""
    print("\n=== Test 7: Información de gramática ===")
    
    jwt = "abc.def.ghi"
    
    parser = JWTParser()
    result = parser.parse(jwt)
    
    print("Gramática:")
    print(f"  Símbolo inicial: {result['grammar']['start_symbol']}")
    print("  Producciones:")
    for prod in result['grammar']['productions']:
        print(f"    {prod}")
    
    assert result['grammar']['start_symbol'] == "JWT"
    assert len(result['grammar']['productions']) == 5
    
    print("Test pasado!")


def test_empty_jwt():
    """Test con JWT vacío"""
    print("\n=== Test 8: JWT vacío ===")
    
    jwt = ""
    
    parser = JWTParser()
    result = parser.parse(jwt)
    
    print(f"Valid: {result['valid']}")
    print(f"Errores: {result['errors']}")
    
    assert result['valid'] == False
    
    print("Test pasado! (detectó JWT vacío)")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("EJECUTANDO TESTS DEL PARSER")
    print("="*60)
    
    test_valid_jwt_syntax()
    test_jwt_missing_parts()
    test_jwt_invalid_characters()
    test_jwt_too_many_parts()
    test_derivation_tree()
    test_derivation_steps()
    test_grammar_information()
    test_empty_jwt()
    
    print("\n" + "="*60)
    print("¡TODOS LOS TESTS DEL PARSER PASARON!")
    print("="*60)