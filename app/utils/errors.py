"""
Excepciones personalizadas para el analizador JWT
"""

class JWTAnalyzerError(Exception):
    """Clase base para todas las excepciones del analizador JWT"""
    def __init__(self, message: str, phase: str = None):
        self.message = message
        self.phase = phase
        super().__init__(self.message)


class LexicalError(JWTAnalyzerError):
    """Error en el análisis léxico"""
    def __init__(self, message: str):
        super().__init__(message, phase="Lexical")


class SyntaxError(JWTAnalyzerError):
    """Error en el análisis sintáctico"""
    def __init__(self, message: str):
        super().__init__(message, phase="Syntax")


class SemanticError(JWTAnalyzerError):
    """Error en el análisis semántico"""
    def __init__(self, message: str):
        super().__init__(message, phase="Semantic")


class DecodingError(JWTAnalyzerError):
    """Error en la decodificación"""
    def __init__(self, message: str):
        super().__init__(message, phase="Decoding")


class EncodingError(JWTAnalyzerError):
    """Error en la codificación"""
    def __init__(self, message: str):
        super().__init__(message, phase="Encoding")


class VerificationError(JWTAnalyzerError):
    """Error en la verificación criptográfica"""
    def __init__(self, message: str):
        super().__init__(message, phase="Verification")


class InvalidTokenError(JWTAnalyzerError):
    """Token JWT inválido o malformado"""
    def __init__(self, message: str):
        super().__init__(message, phase="Validation")