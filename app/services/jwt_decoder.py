from typing import Dict, Any, Tuple
from app.services.lexer import JWTLexer
from app.utils.base64url import base64url_decode
from app.utils.json_utils import parse_json, pretty_print_json
from app.utils.errors import DecodingError


class JWTDecoder:
    def __init__(self):
        self.errors: list = []
        self.warnings: list = []
    
    def decode(self, jwt_string: str) -> Dict[str, Any]:
        self.errors = []
        self.warnings = []
        
        try:
            # Paso 1: Tokenizar con el lexer
            lexer = JWTLexer()
            lexical_result = lexer.tokenize(jwt_string)
            
            if not lexical_result.valid:
                raise DecodingError(
                    f"No se puede decodificar: errores léxicos encontrados"
                )
            
            # Paso 2: Obtener las tres partes
            header_b64, payload_b64, signature_b64 = lexer.get_parts()
            
            # Paso 3: Decodificar cada parte
            header = self._decode_header(header_b64)
            payload = self._decode_payload(payload_b64)
            signature = signature_b64 if signature_b64 else ""  # La firma puede estar vacía (alg: none)
            
            # Resultado
            return {
                "valid": True,
                "header": header,
                "payload": payload,
                "signature": signature,
                "raw": {
                    "header": header_b64,
                    "payload": payload_b64,
                    "signature": signature_b64
                },
                "errors": self.errors,
                "warnings": self.warnings
            }
            
        except DecodingError as e:
            self.errors.append(str(e))
            return {
                "valid": False,
                "header": None,
                "payload": None,
                "signature": None,
                "raw": None,
                "errors": self.errors,
                "warnings": self.warnings
            }
        except Exception as e:
            self.errors.append(f"Error inesperado: {str(e)}")
            return {
                "valid": False,
                "header": None,
                "payload": None,
                "signature": None,
                "raw": None,
                "errors": self.errors,
                "warnings": self.warnings
            }
    
    def _decode_header(self, header_b64: str) -> Dict[str, Any]:
        try:
            header_bytes = base64url_decode(header_b64)
            
            header_string = header_bytes.decode('utf-8')
            
            header_dict = parse_json(header_string)
            
            if 'alg' not in header_dict:
                self.warnings.append(
                    "Header no contiene el campo 'alg' (algoritmo)"
                )
            
            if 'typ' not in header_dict:
                self.warnings.append(
                    "Header no contiene el campo 'typ' (tipo)"
                )
            elif header_dict['typ'] != 'JWT':
                self.warnings.append(
                    f"Campo 'typ' tiene valor '{header_dict['typ']}', "
                    f"se esperaba 'JWT'"
                )
            
            return header_dict
            
        except DecodingError:
            raise
        except UnicodeDecodeError as e:
            raise DecodingError(
                f"Header no es UTF-8 válido: {str(e)}"
            )
        except Exception as e:
            raise DecodingError(
                f"Error al decodificar header: {str(e)}"
            )
    
    def _decode_payload(self, payload_b64: str) -> Dict[str, Any]:
        try:
            payload_bytes = base64url_decode(payload_b64)
            
            payload_string = payload_bytes.decode('utf-8')
            
            payload_dict = parse_json(payload_string)
            
            return payload_dict
            
        except DecodingError:
            raise
        except UnicodeDecodeError as e:
            raise DecodingError(
                f"Payload no es UTF-8 válido: {str(e)}"
            )
        except Exception as e:
            raise DecodingError(
                f"Error al decodificar payload: {str(e)}"
            )
    
    def decode_part(self, part_b64: str, part_name: str = "parte") -> Dict[str, Any]:
        try:
            part_bytes = base64url_decode(part_b64)
            
            part_string = part_bytes.decode('utf-8')
            
            part_dict = parse_json(part_string)
            
            return {
                "valid": True,
                "data": part_dict,
                "raw": part_b64,
                "json_string": part_string
            }
            
        except Exception as e:
            return {
                "valid": False,
                "data": None,
                "raw": part_b64,
                "error": str(e)
            }
    
    def extract_claims(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        standard_claims = {
            'iss': 'Issuer',
            'sub': 'Subject',
            'aud': 'Audience',
            'exp': 'Expiration Time',
            'nbf': 'Not Before',
            'iat': 'Issued At',
            'jti': 'JWT ID'
        }
        
        result = {
            "standard": {},
            "custom": {}
        }
        
        for key, value in payload.items():
            if key in standard_claims:
                result["standard"][key] = {
                    "value": value,
                    "description": standard_claims[key]
                }
            else:
                result["custom"][key] = value
        
        return result
    
    def visualize(self, decoded: Dict[str, Any]) -> str:
        if not decoded["valid"]:
            return f"Error al decodificar:\n" + "\n".join(decoded["errors"])
        
        output = []
        output.append("="*60)
        output.append("JWT DECODIFICADO")
        output.append("="*60)
        
        output.append("\n📋 HEADER:")
        output.append(pretty_print_json(decoded["header"]))
        
        output.append("\n📦 PAYLOAD:")
        output.append(pretty_print_json(decoded["payload"]))
        
        output.append(f"\n🔏 SIGNATURE:")
        output.append(f"  {decoded['signature']}")
        
        claims = self.extract_claims(decoded["payload"])
        
        if claims["standard"]:
            output.append("\n📌 CLAIMS ESTÁNDAR:")
            for claim, info in claims["standard"].items():
                output.append(f"  • {claim} ({info['description']}): {info['value']}")
        
        if claims["custom"]:
            output.append("\n🔧 CLAIMS CUSTOM:")
            for claim, value in claims["custom"].items():
                output.append(f"  • {claim}: {value}")
        
        if decoded["warnings"]:
            output.append("\n⚠️  ADVERTENCIAS:")
            for warning in decoded["warnings"]:
                output.append(f"  • {warning}")
        
        output.append("\n" + "="*60)
        
        return "\n".join(output)