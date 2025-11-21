from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum

class TokenType(str, Enum):
    """Tipos de tokens identificados por el lexer"""
    HEADER = "HEADER"
    PAYLOAD = "PAYLOAD"
    SIGNATURE = "SIGNATURE"
    DELIMITER = "DELIMITER"
    INVALID = "INVALID"
    
class AlgorithmType(str, Enum):
    """Algoritmos soportados para JWT"""
    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"
    NONE = "none"

class Token(BaseModel):
    """Representa un token identificado por el lexer"""
    type: TokenType
    value: str
    position: int = Field(description="Posición en el JWT original")
    length: int = Field(description="Longitud del token")
    
    class Config:
        json_schema_extra = {
            "example": {
                "type": "HEADER",
                "value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                "position": 0,
                "length": 36
            }
        }

class LexicalAnalysisResult(BaseModel):
    """Resultado del análisis léxico"""
    tokens: List[Token]
    valid: bool
    errors: List[str] = []
    warnings: List[str] = []
    
    class Config:
        json_schema_extra = {
            "example": {
                "tokens": [
                    {"type": "HEADER", "value": "eyJ...", "position": 0, "length": 36},
                    {"type": "DELIMITER", "value": ".", "position": 36, "length": 1}
                ],
                "valid": True,
                "errors": [],
                "warnings": []
            }
        }

class JWTHeader(BaseModel):
    alg: str = Field(description="Algoritmo de firma")
    typ: Optional[str] = Field(default="JWT", description="Tipo de token")
    kid: Optional[str] = Field(default=None, description="Key ID")
    
    class Config:
        json_schema_extra = {
            "example": {
                "alg": "HS256",
                "typ": "JWT"
            }
        }

class JWTPayload(BaseModel):
    iss: Optional[str] = Field(default=None, description="Issuer")
    sub: Optional[str] = Field(default=None, description="Subject")
    aud: Optional[str] = Field(default=None, description="Audience")
    exp: Optional[int] = Field(default=None, description="Expiration time")
    nbf: Optional[int] = Field(default=None, description="Not before")
    iat: Optional[int] = Field(default=None, description="Issued at")
    jti: Optional[str] = Field(default=None, description="JWT ID")
    
    # Claims adicionales (custom)
    extra_claims: Optional[Dict[str, Any]] = Field(default_factory=dict)
    
    class Config:
        extra = "allow"
        json_schema_extra = {
            "example": {
                "sub": "1234567890",
                "name": "John Doe",
                "iat": 1516239022
            }
        }

class DecodedJWT(BaseModel):
    """JWT completamente decodificado"""
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: str
    raw_header: str
    raw_payload: str
    raw_signature: str


# ===== MODELOS DE REQUEST/RESPONSE API =====

class AnalyzeRequest(BaseModel):
    """Request para analizar un JWT"""
    token: str = Field(description="JWT completo a analizar")
    secret: Optional[str] = Field(default=None, description="Secret para verificar firma")
    
    class Config:
        json_schema_extra = {
            "example": {
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                "secret": "my-secret-key"
            }
        }


class EncodeRequest(BaseModel):
    """Request para codificar un JWT"""
    header: Dict[str, Any] = Field(description="Header del JWT")
    payload: Dict[str, Any] = Field(description="Payload del JWT")
    secret: str = Field(description="Secret para firmar")
    
    class Config:
        json_schema_extra = {
            "example": {
                "header": {"alg": "HS256", "typ": "JWT"},
                "payload": {"sub": "1234567890", "name": "John Doe"},
                "secret": "my-secret-key"
            }
        }

class AnalyzeResponse(BaseModel):
    """Response completa del análisis"""
    status: str
    lexical_analysis: Optional[LexicalAnalysisResult] = None
    syntactic_analysis: Optional[Dict[str, Any]] = None
    semantic_analysis: Optional[Dict[str, Any]] = None
    decoded: Optional[DecodedJWT] = None
    verification: Optional[Dict[str, Any]] = None
    errors: List[str] = []