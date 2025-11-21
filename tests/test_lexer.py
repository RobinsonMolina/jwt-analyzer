import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.lexer import JWTLexer
from app.models.jwt_models import TokenType


def test_valid_jwt_structure():
    """Test con JWT válido"""
    print("\n=== Test 1: JWT válido ===")
    
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    
    lexer = JWTLexer()
    result = lexer.tokenize(jwt)
    
    print(f"Valid: {result.valid}")
    print(f"Tokens encontrados: {len(result.tokens)}")
    print(f"Errores: {result.errors}")
    
    # Debe tener 5 tokens: HEADER, DELIMITER, PAYLOAD, DELIMITER, SIGNATURE
    assert len(result.tokens) == 5
    assert result.valid == True
    assert len(result.errors) == 0
    
    # Verificar tipos de tokens
    assert result.tokens[0].type == TokenType.HEADER
    assert result.tokens[1].type == TokenType.DELIMITER
    assert result.tokens[2].type == TokenType.PAYLOAD
    assert result.tokens[3].type == TokenType.DELIMITER
    assert result.tokens[4].type == TokenType.SIGNATURE
    
    print("Test pasado!")


def test_jwt_with_invalid_characters():
    """Test con caracteres inválidos"""
    print("\n=== Test 2: JWT con caracteres inválidos ===")
    
    # JWT con + y / (Base64 estándar, no Base64URL)
    jwt = "eyJhbGc+OiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjg+ryP4J3jVmNHl0w5N/XgL0n3I9PlFUP0THsR8U"
    
    lexer = JWTLexer()
    result = lexer.tokenize(jwt)
    
    print(f"Valid: {result.valid}")
    print(f"Errores: {result.errors}")
    
    assert result.valid == False
    assert len(result.errors) > 0
    
    print("Test pasado! (detectó caracteres inválidos)")


def test_jwt_malformed_structure():
    """Test con estructura incorrecta"""
    print("\n=== Test 3: JWT con estructura incorrecta ===")
    
    # JWT con solo 2 partes
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    
    lexer = JWTLexer()
    result = lexer.tokenize(jwt)
    
    print(f"Valid: {result.valid}")
    print(f"Errores: {result.errors}")
    
    assert result.valid == False
    assert len(result.errors) > 0
    assert "3 partes" in result.errors[0]
    
    print("Test pasado! (detectó estructura incorrecta)")


def test_jwt_with_empty_parts():
    """Test con partes vacías"""
    print("\n=== Test 4: JWT con partes vacías ===")
    
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..signature"
    
    lexer = JWTLexer()
    result = lexer.tokenize(jwt)
    
    print(f"Valid: {result.valid}")
    print(f"Errores: {result.errors}")
    
    assert result.valid == False
    assert len(result.errors) > 0
    
    print("Test pasado! (detectó partes vacías)")


def test_get_parts():
    """Test para obtener las partes del JWT"""
    print("\n=== Test 5: Obtener partes del JWT ===")
    
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    
    lexer = JWTLexer()
    result = lexer.tokenize(jwt)
    
    header, payload, signature = lexer.get_parts()
    
    print(f"Header: {header}")
    print(f"Payload: {payload}")
    print(f"Signature: {signature}")
    
    assert header == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    assert payload == "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    assert signature == "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    
    print("Test pasado!")


def test_token_positions():
    """Test de posiciones de tokens"""
    print("\n=== Test 6: Posiciones de tokens ===")
    
    jwt = "abc.def.ghi"
    
    lexer = JWTLexer()
    result = lexer.tokenize(jwt)
    
    print(f"Tokens y posiciones:")
    for token in result.tokens:
        print(f"  {token.type.value}: '{token.value}' en posición {token.position}")
    
    # Verificar posiciones
    assert result.tokens[0].position == 0   # HEADER en 0
    assert result.tokens[1].position == 3   # DELIMITER en 3
    assert result.tokens[2].position == 4   # PAYLOAD en 4
    assert result.tokens[3].position == 7   # DELIMITER en 7
    assert result.tokens[4].position == 8   # SIGNATURE en 8
    
    print("Test pasado!")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("EJECUTANDO TESTS DEL LEXER")
    print("="*60)
    
    test_valid_jwt_structure()
    test_jwt_with_invalid_characters()
    test_jwt_malformed_structure()
    test_jwt_with_empty_parts()
    test_get_parts()
    test_token_positions()
    
    print("\n" + "="*60)
    print("¡TODOS LOS TESTS DEL LEXER PASARON!")
    print("="*60)