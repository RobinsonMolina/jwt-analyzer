import hmac
import hashlib
from typing import Dict, Any, Optional
from app.services.jwt_decoder import JWTDecoder
from app.services.jwt_encoder import JWTEncoder
from app.services.lexer import JWTLexer
from app.utils.errors import VerificationError


class JWTVerifier:
    
    SUPPORTED_ALGORITHMS = {
        'HS256': hashlib.sha256,
        'HS384': hashlib.sha384
    }
    
    def __init__(self):
        self.errors: list = []
        self.warnings: list = []
    
    def verify(self, jwt_string: str, secret: str) -> Dict[str, Any]:
        self.errors = []
        self.warnings = []
        
        try:
            decoder = JWTDecoder()
            decoded = decoder.decode(jwt_string)
            
            if not decoded['valid'] and decoded.get('header') is None:
                raise VerificationError(
                    "No se puede verificar: JWT no pudo decodificarse correctamente"
                )
            
            algorithm = decoded['header'].get('alg')
            
            if not algorithm:
                raise VerificationError("Header no contiene el campo 'alg'")
            
            if algorithm.lower() == 'none':
                return self._verify_none_algorithm(jwt_string, decoded)
            
            if algorithm not in self.SUPPORTED_ALGORITHMS:
                raise VerificationError(
                    f"Algoritmo '{algorithm}' no soportado para verificación. "
                    f"Soportados: {', '.join(self.SUPPORTED_ALGORITHMS.keys())}"
                )
            
            lexer = JWTLexer()
            lexer.tokenize(jwt_string)
            header_b64, payload_b64, signature_b64 = lexer.get_parts()
            
            message = f"{header_b64}.{payload_b64}"
            calculated_signature = self._calculate_signature(message, secret, algorithm)
            
            signature_valid = self._compare_signatures(signature_b64, calculated_signature)
            
            return {
                "valid": signature_valid,
                "algorithm": algorithm,
                "signature_match": signature_valid,
                "expected_signature": calculated_signature,
                "actual_signature": signature_b64,
                "decoded": decoded,
                "errors": self.errors if not signature_valid else [],
                "warnings": self.warnings
            }
            
        except VerificationError as e:
            self.errors.append(str(e))
            return {
                "valid": False,
                "algorithm": None,
                "signature_match": False,
                "expected_signature": None,
                "actual_signature": None,
                "decoded": None,
                "errors": self.errors,
                "warnings": self.warnings
            }
        except Exception as e:
            self.errors.append(f"Error inesperado al verificar: {str(e)}")
            return {
                "valid": False,
                "algorithm": None,
                "signature_match": False,
                "expected_signature": None,
                "actual_signature": None,
                "decoded": None,
                "errors": self.errors,
                "warnings": self.warnings
            }
    
    def _calculate_signature(self, message: str, secret: str, algorithm: str) -> str:
        try:
            from app.utils.base64url import base64url_encode
            
            hash_func = self.SUPPORTED_ALGORITHMS[algorithm]
            
            signature_bytes = hmac.new(
                secret.encode('utf-8'),
                message.encode('utf-8'),
                hash_func
            ).digest()
            
            signature_b64 = base64url_encode(signature_bytes)
            
            return signature_b64
            
        except Exception as e:
            raise VerificationError(f"Error al calcular firma: {str(e)}")
    
    def _compare_signatures(self, signature1: str, signature2: str) -> bool:
        try:
            match = hmac.compare_digest(signature1, signature2)
            
            if not match:
                self.errors.append(
                    "Firma inválida: el token ha sido modificado o el secret es incorrecto"
                )
            
            return match
            
        except Exception as e:
            self.errors.append(f"Error al comparar firmas: {str(e)}")
            return False
    
    def _verify_none_algorithm(self, jwt_string: str, decoded: Dict[str, Any]) -> Dict[str, Any]:
        self.warnings.append(
            "⚠️  ADVERTENCIA: Token con algoritmo 'none' detectado. "
            "Este token NO está firmado y NO es seguro."
        )
        
        # Verificar que termine en '.' o tenga firma vacía
        if not (jwt_string.endswith('.') or jwt_string.endswith('..')):
            self.warnings.append(
                "Token con algoritmo 'none' pero tiene firma no vacía. Posible manipulación."
            )
        
        return {
            "valid": True,  # Técnicamente válido, pero inseguro
            "algorithm": "none",
            "signature_match": None,  # No aplica
            "expected_signature": None,
            "actual_signature": None,
            "decoded": decoded,
            "errors": [],
            "warnings": self.warnings
        }
    
    def verify_and_decode(self, jwt_string: str, secret: str) -> Dict[str, Any]:
        verification = self.verify(jwt_string, secret)
        
        if not verification['valid']:
            return {
                "valid": False,
                "verified": False,
                "decoded": None,
                "errors": verification['errors'],
                "warnings": verification['warnings']
            }
        
        return {
            "valid": True,
            "verified": True,
            "decoded": verification['decoded'],
            "algorithm": verification['algorithm'],
            "errors": [],
            "warnings": verification['warnings']
        }
    
    def detect_tampering(self, jwt_string: str, secret: str) -> Dict[str, Any]:
        result = {
            "is_tampered": False,
            "tampering_indicators": [],
            "verification_result": None
        }
        
        verification = self.verify(jwt_string, secret)
        result["verification_result"] = verification
        
        # Indicador 1: Firma no coincide
        if not verification['signature_match'] and verification['algorithm'] != 'none':
            result["is_tampered"] = True
            result["tampering_indicators"].append(
                "Firma no coincide - token modificado o secret incorrecto"
            )
        
        # Indicador 2: Algoritmo 'none' sospechoso
        if verification.get('algorithm') == 'none':
            result["tampering_indicators"].append(
                "Algoritmo 'none' detectado - token sin protección criptográfica"
            )
        
        # Indicador 3: Errores de decodificación
        if verification.get('decoded') and not verification['decoded']['valid']:
            result["is_tampered"] = True
            result["tampering_indicators"].append(
                "Errores al decodificar - posible manipulación de estructura"
            )
        
        return result
    
    def verify_with_multiple_secrets(
        self, 
        jwt_string: str, 
        secrets: list
    ) -> Dict[str, Any]:
        for i, secret in enumerate(secrets):
            verification = self.verify(jwt_string, secret)
            
            if verification['valid']:
                return {
                    "valid": True,
                    "matched_secret_index": i,
                    "verification": verification
                }
        
        return {
            "valid": False,
            "matched_secret_index": None,
            "error": "Ningún secret coincide con la firma del token"
        }