from fastapi import APIRouter, HTTPException, status
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from app.services.lexer import JWTLexer
from app.services.parser import JWTParser
from app.services.semantic import SemanticAnalyzer
from app.services.jwt_decoder import JWTDecoder
from app.services.jwt_encoder import JWTEncoder
from app.services.verifier import JWTVerifier
import time
from app.database.logs import save_analyze_log, save_encode_log

router = APIRouter()

class AnalyzeRequest(BaseModel):
    token: str = Field(description="JWT completo a analizar")
    secret: Optional[str] = Field(default=None, description="Secret para verificar firma (opcional)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                "secret": "my-secret-key"
            }
        }
class EncodeRequest(BaseModel):
    payload: Dict[str, Any] = Field(description="Claims del payload")
    secret: str = Field(description="Clave secreta para firmar")
    algorithm: Optional[str] = Field(default="HS256", description="Algoritmo de firma")
    header: Optional[Dict[str, Any]] = Field(default=None, description="Header personalizado (opcional)")
    expires_in: Optional[int] = Field(default=None, description="Segundos hasta expiración (opcional)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "payload": {"sub": "1234567890", "name": "John Doe"},
                "secret": "my-secret-key",
                "algorithm": "HS256",
                "expires_in": 3600
            }
        }


class DecodeRequest(BaseModel):
    token: str = Field(description="JWT a decodificar")
    
    class Config:
        json_schema_extra = {
            "example": {
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
            }
        }


class VerifyRequest(BaseModel):
    token: str = Field(description="JWT a verificar")
    secret: str = Field(description="Clave secreta")
    
    class Config:
        json_schema_extra = {
            "example": {
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                "secret": "my-secret-key"
            }
        }

@router.get("/")
async def api_root():
    """Endpoint raíz de la API JWT"""
    return {
        "message": "JWT Analyzer API",
        "version": "1.0.0",
        "endpoints": {
            "analyze": "POST /analyze - Análisis completo de JWT (todas las fases)",
            "encode": "POST /encode - Codifica un nuevo JWT",
            "decode": "POST /decode - Decodifica un JWT",
            "verify": "POST /verify - Verifica la firma de un JWT"
        }
    }


@router.post("/analyze")
async def analyze_jwt(request: AnalyzeRequest):
    try:
        start_time = time.time()
        
        token = request.token.strip()
        result = {
            "token": token,
            "phases": {}
        }
        
        # FASE 1: Análisis Léxico
        try:
            lexer = JWTLexer()
            lexical_result = lexer.tokenize(token)
            result["phases"]["lexical"] = {
                "valid": lexical_result.valid,
                "tokens": [
                    {
                        "type": t.type.value,
                        "value": t.value[:50] + "..." if len(t.value) > 50 else t.value,
                        "position": t.position,
                        "length": t.length
                    }
                    for t in lexical_result.tokens
                ],
                "errors": lexical_result.errors,
                "warnings": lexical_result.warnings
            }
        except Exception as e:
            result["phases"]["lexical"] = {
                "valid": False,
                "errors": [str(e)]
            }
        
        # FASE 2: Análisis Sintáctico
        try:
            parser = JWTParser()
            syntactic_result = parser.parse(token)
            result["phases"]["syntactic"] = {
                "valid": syntactic_result["valid"],
                "grammar": syntactic_result["grammar"],
                "derivation_steps": parser.get_derivation_steps(),
                "errors": syntactic_result["errors"],
                "warnings": syntactic_result["warnings"]
            }
        except Exception as e:
            result["phases"]["syntactic"] = {
                "valid": False,
                "errors": [str(e)]
            }
        
        # FASE 4: Decodificación
        try:
            decoder = JWTDecoder()
            decoded_result = decoder.decode(token)
            result["phases"]["decoding"] = {
                "valid": decoded_result["valid"],
                "header": decoded_result.get("header"),
                "payload": decoded_result.get("payload"),
                "signature": decoded_result.get("signature"),
                "errors": decoded_result["errors"],
                "warnings": decoded_result["warnings"]
            }
            result["decoded"] = decoded_result
        except Exception as e:
            result["phases"]["decoding"] = {
                "valid": False,
                "errors": [str(e)]
            }
        
        # FASE 3: Análisis Semántico
        try:
            semantic_analyzer = SemanticAnalyzer()
            semantic_result = semantic_analyzer.analyze(token)
            result["phases"]["semantic"] = {
                "valid": semantic_result["valid"],
                "symbol_table": semantic_result["symbol_table"],
                "temporal_validation": semantic_result["temporal_validation"],
                "header_summary": semantic_result["header_validation"],
                "payload_summary": semantic_result["payload_validation"],
                "errors": semantic_result["errors"],
                "warnings": semantic_result["warnings"]
            }
        except Exception as e:
            result["phases"]["semantic"] = {
                "valid": False,
                "errors": [str(e)]
            }
        
        # FASE 6: Verificación Criptográfica (solo si se proporciona secret)
        if request.secret:
            try:
                verifier = JWTVerifier()
                verification_result = verifier.verify(token, request.secret)
                result["phases"]["verification"] = {
                    "valid": verification_result["valid"],
                    "signature_match": verification_result["signature_match"],
                    "algorithm": verification_result["algorithm"],
                    "errors": verification_result["errors"],
                    "warnings": verification_result["warnings"]
                }
            except Exception as e:
                result["phases"]["verification"] = {
                    "valid": False,
                    "errors": [str(e)]
                }
        else:
            result["phases"]["verification"] = {
                "skipped": True,
                "message": "Secret no proporcionado, verificación omitida"
            }
        
        # Determinar validez general
        all_phases_valid = all(
            phase.get("valid", False) 
            for phase_name, phase in result["phases"].items()
            if phase_name != "verification" and "valid" in phase
        )
        
        result["overall_valid"] = all_phases_valid
        result["status"] = "success"
        
        execution_time = int((time.time() - start_time) * 1000)
        
        # Guardar log en MongoDB
        try:
            await save_analyze_log(
                token=token,
                secret=request.secret,
                result=result,
                execution_time_ms=execution_time
            )
        except Exception as e:
            print(f"Error guardando log: {e}")
        
        return result
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error al analizar JWT: {str(e)}"
        )

@router.post("/encode")
async def encode_jwt(request: EncodeRequest):
    try:
        encoder = JWTEncoder()
        
        if request.expires_in:
            result = encoder.create_token_with_expiration(
                payload=request.payload,
                secret=request.secret,
                expires_in_seconds=request.expires_in,
                algorithm=request.algorithm
            )
        else:
            result = encoder.encode(
                payload=request.payload,
                secret=request.secret,
                algorithm=request.algorithm,
                header=request.header
            )
        
        if not result["valid"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"errors": result["errors"]}
            )
            
        # Guardar log en MongoDB
        try:
            await save_encode_log(
                payload=request.payload,
                secret=request.secret,
                algorithm=request.algorithm,
                expires_in=request.expires_in,
                result=result
            )
        except Exception as e:
            print(f"Error guardando log: {e}")
        
        return {
            "status": "success",
            "token": result["token"],
            "parts": result["parts"],
            "decoded": result["decoded"],
            "algorithm": result["algorithm"],
            "warnings": result["warnings"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al codificar JWT: {str(e)}"
        )

@router.post("/decode")
async def decode_jwt(request: DecodeRequest):
    try:
        decoder = JWTDecoder()
        result = decoder.decode(request.token)
        
        if not result["valid"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"errors": result["errors"]}
            )
        
        visualization = decoder.visualize(result)
        
        return {
            "status": "success",
            "header": result["header"],
            "payload": result["payload"],
            "signature": result["signature"],
            "raw_parts": result["raw"],
            "visualization": visualization,
            "warnings": result["warnings"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al decodificar JWT: {str(e)}"
        )

@router.post("/verify")
async def verify_jwt(request: VerifyRequest):
    try:
        verifier = JWTVerifier()
        result = verifier.verify(request.token, request.secret)
        
        return {
            "status": "success",
            "valid": result["valid"],
            "signature_match": result["signature_match"],
            "algorithm": result["algorithm"],
            "decoded": result["decoded"],
            "errors": result["errors"],
            "warnings": result["warnings"]
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al verificar JWT: {str(e)}"
        )