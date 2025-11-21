import hmac
import hashlib
from typing import Dict, Any, Optional
from datetime import datetime, timezone, timedelta
from app.utils.base64url import base64url_encode
from app.utils.json_utils import to_json_string
from app.utils.errors import EncodingError


class JWTEncoder:
    
    SUPPORTED_ALGORITHMS = {
        'HS256': hashlib.sha256,
        'HS384': hashlib.sha384,
        'HS512': hashlib.sha512
    }
    
    def __init__(self):
        self.errors: list = []
        self.warnings: list = []
    
    def encode(
        self, 
        payload: Dict[str, Any],
        secret: str,
        algorithm: str = 'HS256',
        header: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        self.errors = []
        self.warnings = []
        
        try:
            if algorithm not in self.SUPPORTED_ALGORITHMS:
                raise EncodingError(
                    f"Algoritmo '{algorithm}' no soportado. "
                    f"Soportados: {', '.join(self.SUPPORTED_ALGORITHMS.keys())}"
                )
            
            if not secret:
                raise EncodingError("La clave secreta no puede estar vacía")
            
            if header is None:
                header = self._create_default_header(algorithm)
            else:
                header = self._validate_header(header, algorithm)
            
            payload = self._validate_payload(payload)
            
            header_json = to_json_string(header)
            
            payload_json = to_json_string(payload)
            
            header_b64 = base64url_encode(header_json.encode('utf-8'))
            
            payload_b64 = base64url_encode(payload_json.encode('utf-8'))
            
            message = f"{header_b64}.{payload_b64}"
            
            signature = self._create_signature(message, secret, algorithm)
            
            jwt_token = f"{message}.{signature}"
            
            return {
                "valid": True,
                "token": jwt_token,
                "parts": {
                    "header": header_b64,
                    "payload": payload_b64,
                    "signature": signature
                },
                "decoded": {
                    "header": header,
                    "payload": payload
                },
                "algorithm": algorithm,
                "errors": self.errors,
                "warnings": self.warnings
            }
            
        except EncodingError as e:
            self.errors.append(str(e))
            return {
                "valid": False,
                "token": None,
                "parts": None,
                "decoded": None,
                "algorithm": algorithm,
                "errors": self.errors,
                "warnings": self.warnings
            }
        except Exception as e:
            self.errors.append(f"Error inesperado al codificar: {str(e)}")
            return {
                "valid": False,
                "token": None,
                "parts": None,
                "decoded": None,
                "algorithm": algorithm,
                "errors": self.errors,
                "warnings": self.warnings
            }
    
    def _create_default_header(self, algorithm: str) -> Dict[str, Any]:
        return {
            "alg": algorithm,
            "typ": "JWT"
        }
    
    def _validate_header(self, header: Dict[str, Any], algorithm: str) -> Dict[str, Any]:
        if not isinstance(header, dict):
            raise EncodingError("El header debe ser un diccionario")
        
        if 'alg' not in header:
            header['alg'] = algorithm
            self.warnings.append(f"Campo 'alg' no proporcionado, usando '{algorithm}'")
        elif header['alg'] != algorithm:
            self.warnings.append(
                f"Algoritmo en header ('{header['alg']}') difiere del especificado ('{algorithm}'). "
                f"Se usará '{algorithm}'"
            )
            header['alg'] = algorithm
        
        if 'typ' not in header:
            header['typ'] = 'JWT'
            self.warnings.append("Campo 'typ' no proporcionado, usando 'JWT'")
        
        return header
    
    def _validate_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            raise EncodingError("El payload debe ser un diccionario")
        
        if not payload:
            self.warnings.append("El payload está vacío")
        
        if 'exp' in payload and not isinstance(payload['exp'], (int, float)):
            raise EncodingError("Claim 'exp' debe ser un número (timestamp)")
        
        if 'iat' in payload and not isinstance(payload['iat'], (int, float)):
            raise EncodingError("Claim 'iat' debe ser un número (timestamp)")
        
        if 'nbf' in payload and not isinstance(payload['nbf'], (int, float)):
            raise EncodingError("Claim 'nbf' debe ser un número (timestamp)")
        
        if 'iat' not in payload:
            self.warnings.append(
                "Se recomienda incluir 'iat' (issued at) en el payload"
            )
        
        return payload
    
    def _create_signature(self, message: str, secret: str, algorithm: str) -> str:
        try:
            hash_func = self.SUPPORTED_ALGORITHMS[algorithm]
            
            signature_bytes = hmac.new(
                secret.encode('utf-8'),
                message.encode('utf-8'),
                hash_func
            ).digest()
            
            signature_b64 = base64url_encode(signature_bytes)
            
            return signature_b64
            
        except Exception as e:
            raise EncodingError(f"Error al crear firma: {str(e)}")
    
    def create_token_with_expiration(
        self,
        payload: Dict[str, Any],
        secret: str,
        expires_in_seconds: int = 3600,
        algorithm: str = 'HS256'
    ) -> Dict[str, Any]:
        current_time = int(datetime.now(timezone.utc).timestamp())
        
        payload_with_time = payload.copy()
        payload_with_time['iat'] = current_time
        payload_with_time['exp'] = current_time + expires_in_seconds
        
        return self.encode(payload_with_time, secret, algorithm)
    
    def create_token_without_signature(
        self,
        payload: Dict[str, Any],
        header: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        self.warnings.append(
            "⚠️  ADVERTENCIA: Creando token sin firma (algoritmo 'none'). "
            "Esto es INSEGURO y solo debe usarse para testing."
        )
        
        if header is None:
            header = {"alg": "none", "typ": "JWT"}
        else:
            header['alg'] = 'none'
        
        try:
            header_json = to_json_string(header)
            payload_json = to_json_string(payload)
            
            header_b64 = base64url_encode(header_json.encode('utf-8'))
            payload_b64 = base64url_encode(payload_json.encode('utf-8'))
            
            jwt_token = f"{header_b64}.{payload_b64}."
            
            return {
                "valid": True,
                "token": jwt_token,
                "parts": {
                    "header": header_b64,
                    "payload": payload_b64,
                    "signature": ""
                },
                "decoded": {
                    "header": header,
                    "payload": payload
                },
                "algorithm": "none",
                "errors": [],
                "warnings": self.warnings
            }
            
        except Exception as e:
            return {
                "valid": False,
                "token": None,
                "error": str(e),
                "warnings": self.warnings
            }