from typing import List, Dict, Any, Optional
from app.models.jwt_models import Token, TokenType, LexicalAnalysisResult
from app.services.lexer import JWTLexer
from app.utils.errors import SyntaxError as JWTSyntaxError


class JWTParser:
    
    def __init__(self):
        self.tokens: List[Token] = []
        self.current_pos: int = 0
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.derivation_tree: Dict[str, Any] = {}
    
    def parse(self, jwt_string: str) -> Dict[str, Any]:
        self.errors = []
        self.warnings = []
        self.current_pos = 0
        
        lexer = JWTLexer()
        lexical_result = lexer.tokenize(jwt_string)
        
        if not lexical_result.valid:
            self.errors.append("Análisis léxico falló, no se puede continuar con análisis sintáctico")
            self.errors.extend(lexical_result.errors)
            return self._build_result(valid=False, lexical_result=lexical_result)
        
        self.tokens = lexical_result.tokens
        
        try:
            self.derivation_tree = self._parse_jwt()
            valid = len(self.errors) == 0
            return self._build_result(valid=valid, lexical_result=lexical_result)
        
        except JWTSyntaxError as e:
            self.errors.append(str(e))
            return self._build_result(valid=False, lexical_result=lexical_result)
    
    def _parse_jwt(self) -> Dict[str, Any]:
        tree = {
            "rule": "JWT → HEADER '.' PAYLOAD '.' SIGNATURE",
            "children": []
        }
        
        header_node = self._expect_token(TokenType.HEADER, "HEADER")
        tree["children"].append(header_node)
        
        delimiter1_node = self._expect_token(TokenType.DELIMITER, "DELIMITER")
        tree["children"].append(delimiter1_node)
        
        payload_node = self._expect_token(TokenType.PAYLOAD, "PAYLOAD")
        tree["children"].append(payload_node)
        
        delimiter2_node = self._expect_token(TokenType.DELIMITER, "DELIMITER")
        tree["children"].append(delimiter2_node)
        
        signature_node = self._expect_token(TokenType.SIGNATURE, "SIGNATURE")
        tree["children"].append(signature_node)
        
        if self.current_pos < len(self.tokens):
            extra_tokens = len(self.tokens) - self.current_pos
            self.errors.append(
                f"Se encontraron {extra_tokens} token(s) adicional(es) después de SIGNATURE"
            )
        
        return tree
    
    def _expect_token(self, expected_type: TokenType, symbol: str) -> Dict[str, Any]:
        if self.current_pos >= len(self.tokens):
            raise JWTSyntaxError(
                f"Se esperaba {symbol} pero se alcanzó el fin del token"
            )
        
        current_token = self.tokens[self.current_pos]
        
        if current_token.type != expected_type:
            raise JWTSyntaxError(
                f"Se esperaba {symbol} ({expected_type.value}) "
                f"pero se encontró {current_token.type.value} "
                f"en la posición {current_token.position}"
            )
        
        self.current_pos += 1
        
        node = {
            "symbol": symbol,
            "token_type": current_token.type.value,
            "value": current_token.value,
            "position": current_token.position,
            "length": current_token.length,
            "production": f"{symbol} → BASE64URL" if expected_type != TokenType.DELIMITER else f"{symbol} → '.'"
        }
        
        self._validate_token_content(current_token, symbol)
        
        return node
    
    def _validate_token_content(self, token: Token, symbol: str) -> None:
        if token.type == TokenType.DELIMITER:
            if token.value != '.':
                self.errors.append(
                    f"Delimitador inválido: se esperaba '.' pero se encontró '{token.value}'"
                )
            return
        
        if len(token.value) < 4 and token.type != TokenType.SIGNATURE:
            self.warnings.append(
                f"{symbol} tiene longitud muy corta ({len(token.value)} caracteres), "
                f"posible token malformado"
            )
        
        if token.type in [TokenType.HEADER, TokenType.PAYLOAD]:
            remainder = len(token.value) % 4
            if remainder not in [0, 2, 3]:
                self.warnings.append(
                    f"{symbol} tiene longitud no estándar para Base64 "
                    f"({len(token.value)} chars, resto={remainder})"
                )
    
    def _build_result(
        self, 
        valid: bool, 
        lexical_result: Optional[LexicalAnalysisResult] = None
    ) -> Dict[str, Any]:
        return {
            "valid": valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "derivation_tree": self.derivation_tree if valid else None,
            "grammar": {
                "start_symbol": "JWT",
                "productions": [
                    "JWT → HEADER '.' PAYLOAD '.' SIGNATURE",
                    "HEADER → BASE64URL",
                    "PAYLOAD → BASE64URL",
                    "SIGNATURE → BASE64URL",
                    "BASE64URL → (A-Z | a-z | 0-9 | '-' | '_')+"
                ]
            },
            "lexical_analysis": {
                "valid": lexical_result.valid if lexical_result else False,
                "tokens_count": len(lexical_result.tokens) if lexical_result else 0,
                "errors": lexical_result.errors if lexical_result else []
            }
        }
    
    def get_derivation_steps(self) -> List[str]:
        if not self.derivation_tree:
            return []
        
        steps = [
            "1. JWT",
            "2. JWT → HEADER '.' PAYLOAD '.' SIGNATURE",
            "3. HEADER '.' PAYLOAD '.' SIGNATURE → BASE64URL '.' PAYLOAD '.' SIGNATURE",
            "4. BASE64URL '.' PAYLOAD '.' SIGNATURE → BASE64URL '.' BASE64URL '.' SIGNATURE",
            "5. BASE64URL '.' BASE64URL '.' SIGNATURE → BASE64URL '.' BASE64URL '.' BASE64URL"
        ]
        
        return steps