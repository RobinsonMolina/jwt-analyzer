from typing import List, Tuple
from app.models.jwt_models import Token, TokenType, LexicalAnalysisResult
from app.utils.base64url import is_valid_base64url
from app.utils.errors import LexicalError


class JWTLexer:
    DELIMITER = '.'
    
    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.tokens: List[Token] = []
    
    def tokenize(self, jwt_string: str) -> LexicalAnalysisResult:
        self.errors = []
        self.warnings = []
        self.tokens = []
        
        if not jwt_string:
            self.errors.append("El token JWT está vacío")
            return self._build_result(valid=False)
        
        if not isinstance(jwt_string, str):
            self.errors.append("El token JWT debe ser una cadena de texto")
            return self._build_result(valid=False)
        
        jwt_string = jwt_string.strip()
        
        parts = jwt_string.split(self.DELIMITER)
        
        if len(parts) != 3:
            self.errors.append(
                f"Estructura JWT inválida: se esperaban 3 partes separadas por '.', "
                f"se encontraron {len(parts)}"
            )
            return self._build_result(valid=False)
        
        header_part, payload_part, signature_part = parts
        
        position = 0
        
        header_token = self._create_token(
            TokenType.HEADER,
            header_part,
            position
        )
        self._validate_token(header_token)
        self.tokens.append(header_token)
        position += len(header_part)
        
        delimiter1_token = self._create_token(
            TokenType.DELIMITER,
            self.DELIMITER,
            position
        )
        self.tokens.append(delimiter1_token)
        position += 1
        
        payload_token = self._create_token(
            TokenType.PAYLOAD,
            payload_part,
            position
        )
        self._validate_token(payload_token)
        self.tokens.append(payload_token)
        position += len(payload_part)
        
        delimiter2_token = self._create_token(
            TokenType.DELIMITER,
            self.DELIMITER,
            position
        )
        self.tokens.append(delimiter2_token)
        position += 1
        
        signature_token = self._create_token(
            TokenType.SIGNATURE,
            signature_part,
            position
        )
        if signature_part:
            self._validate_token(signature_token)
        else:
            self.warnings.append("Signature está vacía (posible algoritmo 'none')")
        self.tokens.append(signature_token)
        
        valid = len(self.errors) == 0
        return self._build_result(valid=valid)
    
    def _create_token(self, token_type: TokenType, value: str, position: int) -> Token:
        """Crea un token"""
        return Token(
            type=token_type,
            value=value,
            position=position,
            length=len(value)
        )
    
    def _validate_token(self, token: Token) -> None:
        # Solo validar tokens que no sean delimitadores
        if token.type == TokenType.DELIMITER:
            return
        
        # Verificar que no esté vacío
        if not token.value:
            self.errors.append(
                f"{token.type.value} está vacío en la posición {token.position}"
            )
            return
        
        if not is_valid_base64url(token.value):
            invalid_chars = [
                c for c in token.value 
                if not (c.isalnum() or c in ['-', '_'])
            ]
            self.errors.append(
                f"{token.type.value} contiene caracteres inválidos: {set(invalid_chars)} "
                f"en la posición {token.position}"
            )
        
        # Advertencias para tokens muy cortos (posibles errores)
        if len(token.value) < 4 and token.type != TokenType.SIGNATURE:
            self.warnings.append(
                f"{token.type.value} es muy corto ({len(token.value)} caracteres), "
                f"posible token malformado"
            )
    
    def _build_result(self, valid: bool) -> LexicalAnalysisResult:
        return LexicalAnalysisResult(
            tokens=self.tokens,
            valid=valid,
            errors=self.errors,
            warnings=self.warnings
        )
    
    def get_token_by_type(self, token_type: TokenType) -> Token:
        for token in self.tokens:
            if token.type == token_type:
                return token
        raise LexicalError(f"Token de tipo {token_type} no encontrado")
    
    def get_parts(self) -> Tuple[str, str, str]:
        try:
            header = self.get_token_by_type(TokenType.HEADER).value
            payload = self.get_token_by_type(TokenType.PAYLOAD).value
            signature = self.get_token_by_type(TokenType.SIGNATURE).value
            return header, payload, signature
        except LexicalError as e:
            raise LexicalError(f"No se pudieron extraer las partes del JWT: {str(e)}")