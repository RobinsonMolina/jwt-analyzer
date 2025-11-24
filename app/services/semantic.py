from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from app.services.jwt_decoder import JWTDecoder
from app.utils.errors import SemanticError


class SymbolTable:
    
    def __init__(self):
        self.symbols: Dict[str, Dict[str, Any]] = {}
    
    def add(self, name: str, value: Any, claim_type: str, scope: str):
        self.symbols[name] = {
            "value": value,
            "type": claim_type,
            "scope": scope,
            "standard": self._is_standard_claim(name, scope)
        }
    
    def get(self, name: str) -> Optional[Dict[str, Any]]:
        return self.symbols.get(name)
    
    def exists(self, name: str) -> bool:
        return name in self.symbols
    
    def get_by_scope(self, scope: str) -> Dict[str, Dict[str, Any]]:
        return {
            name: info 
            for name, info in self.symbols.items() 
            if info["scope"] == scope
        }
    
    def _is_standard_claim(self, name: str, scope: str) -> bool:
        standard_header = ['alg', 'typ', 'kid', 'jku', 'jwk', 'x5u', 'x5c', 'x5t', 'cty']
        standard_payload = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti']
        
        if scope == "header":
            return name in standard_header
        elif scope == "payload":
            return name in standard_payload
        return False
    
    def to_dict(self) -> Dict[str, Dict[str, Any]]:
        return self.symbols.copy()


class SemanticAnalyzer:
    
    SUPPORTED_ALGORITHMS = ['HS256', 'HS384']
    
    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.symbol_table = SymbolTable()
    
    def analyze(self, jwt_string: str) -> Dict[str, Any]:
        self.errors = []
        self.warnings = []
        self.symbol_table = SymbolTable()
        
        try:
            # Decodificar primero
            decoder = JWTDecoder()
            decoded = decoder.decode(jwt_string)
            
            if not decoded['valid']:
                raise SemanticError(
                    "No se puede hacer análisis semántico: JWT no pudo decodificarse"
                )
            
            header = decoded['header']
            payload = decoded['payload']
            
            # Análisis del header
            self._analyze_header(header)
            
            # Análisis del payload
            self._analyze_payload(payload)
            
            # Validaciones temporales
            temporal_result = self._validate_temporal_claims(payload)
            
            # Resultado
            valid = len(self.errors) == 0
            
            return {
                "valid": valid,
                "errors": self.errors,
                "warnings": self.warnings,
                "symbol_table": self.symbol_table.to_dict(),
                "temporal_validation": temporal_result,
                "header_validation": self._get_header_summary(),
                "payload_validation": self._get_payload_summary()
            }
            
        except SemanticError as e:
            self.errors.append(str(e))
            return {
                "valid": False,
                "errors": self.errors,
                "warnings": self.warnings,
                "symbol_table": {},
                "temporal_validation": None,
                "header_validation": None,
                "payload_validation": None
            }
    
    def _analyze_header(self, header: Dict[str, Any]) -> None:
        # Campo obligatorio: alg
        if 'alg' not in header:
            self.errors.append("Campo obligatorio 'alg' faltante en header")
        else:
            alg = header['alg']
            self.symbol_table.add('alg', alg, type(alg).__name__, 'header')
            
            # Validar tipo
            if not isinstance(alg, str):
                self.errors.append(
                    f"Campo 'alg' debe ser string, se encontró {type(alg).__name__}"
                )
            
            # Validar algoritmo soportado
            elif alg not in self.SUPPORTED_ALGORITHMS:
                self.errors.append(
                    f"Algoritmo no permitido: '{alg}'. Solo se permiten HS256 y HS384."
                )
            
            if alg == 'none':
                self.warnings.append(
                    "Algoritmo 'none' detectado: el token NO está firmado (inseguro)"
                )
        
        if 'typ' not in header:
            self.warnings.append("Campo recomendado 'typ' faltante en header")
        else:
            typ = header['typ']
            self.symbol_table.add('typ', typ, type(typ).__name__, 'header')
            
            if not isinstance(typ, str):
                self.errors.append(
                    f"Campo 'typ' debe ser string, se encontró {type(typ).__name__}"
                )
            
            elif typ != 'JWT':
                self.warnings.append(
                    f"Campo 'typ' tiene valor '{typ}', se esperaba 'JWT'"
                )
        
        for key, value in header.items():
            if key not in ['alg', 'typ']:
                self.symbol_table.add(key, value, type(value).__name__, 'header')
    
    def _analyze_payload(self, payload: Dict[str, Any]) -> None:
        # Claims estándar y sus tipos esperados
        standard_claims = {
            'iss': str,    # Issuer
            'sub': str,    # Subject
            'aud': (str, list),  # Audience (puede ser string o array)
            'exp': (int, float),  # Expiration time
            'nbf': (int, float),  # Not before
            'iat': (int, float),  # Issued at
            'jti': str     # JWT ID
        }
        
        # Validar tipos de claims estándar
        for claim, expected_type in standard_claims.items():
            if claim in payload:
                value = payload[claim]
                self.symbol_table.add(claim, value, type(value).__name__, 'payload')
                
                # Validar tipo
                if not isinstance(value, expected_type):
                    if isinstance(expected_type, tuple):
                        type_names = ' o '.join(t.__name__ for t in expected_type)
                        self.errors.append(
                            f"Claim '{claim}' debe ser {type_names}, "
                            f"se encontró {type(value).__name__}"
                        )
                    else:
                        self.errors.append(
                            f"Claim '{claim}' debe ser {expected_type.__name__}, "
                            f"se encontró {type(value).__name__}"
                        )
        
        # Advertencia si no hay claims estándar
        has_standard = any(claim in payload for claim in standard_claims.keys())
        if not has_standard:
            self.warnings.append(
                "El payload no contiene ningún claim estándar (iss, sub, aud, exp, etc.)"
            )
        
        # Registrar claims custom
        for key, value in payload.items():
            if key not in standard_claims:
                self.symbol_table.add(key, value, type(value).__name__, 'payload')
    
    def _validate_temporal_claims(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        current_time = datetime.now(timezone.utc).timestamp()
        
        result = {
            "current_time": int(current_time),
            "exp": None,
            "iat": None,
            "nbf": None,
            "is_expired": False,
            "is_not_yet_valid": False,
            "age_seconds": None
        }
        
        # Validar exp (expiration)
        if 'exp' in payload:
            exp = payload['exp']
            result['exp'] = exp
            
            if isinstance(exp, (int, float)):
                if current_time > exp:
                    result['is_expired'] = True
                    self.errors.append(
                        f"Token expirado: exp={exp} "
                        f"({datetime.fromtimestamp(exp, timezone.utc).isoformat()})"
                    )
                else:
                    time_until_exp = exp - current_time
                    result['expires_in_seconds'] = int(time_until_exp)
            else:
                self.errors.append(
                    f"Claim 'exp' tiene tipo inválido: {type(exp).__name__}"
                )
        
        # Validar nbf (not before)
        if 'nbf' in payload:
            nbf = payload['nbf']
            result['nbf'] = nbf
            
            if isinstance(nbf, (int, float)):
                if current_time < nbf:
                    result['is_not_yet_valid'] = True
                    self.errors.append(
                        f"Token aún no válido: nbf={nbf} "
                        f"({datetime.fromtimestamp(nbf, timezone.utc).isoformat()})"
                    )
            else:
                self.errors.append(
                    f"Claim 'nbf' tiene tipo inválido: {type(nbf).__name__}"
                )
        
        # Validar iat (issued at)
        if 'iat' in payload:
            iat = payload['iat']
            result['iat'] = iat
            
            if isinstance(iat, (int, float)):
                age = current_time - iat
                result['age_seconds'] = int(age)
                
                # Advertencia si el token es muy antiguo (más de 1 año)
                if age > 365 * 24 * 60 * 60:
                    self.warnings.append(
                        f"Token muy antiguo: emitido hace {int(age / 86400)} días"
                    )
                
                # Advertencia si iat es en el futuro
                if iat > current_time:
                    self.warnings.append(
                        f"Claim 'iat' está en el futuro: {datetime.fromtimestamp(iat, timezone.utc).isoformat()}"
                    )
            else:
                self.errors.append(
                    f"Claim 'iat' tiene tipo inválido: {type(iat).__name__}"
                )
        
        # Validación de coherencia: nbf <= current <= exp
        if 'nbf' in payload and 'exp' in payload:
            nbf = payload['nbf']
            exp = payload['exp']
            if isinstance(nbf, (int, float)) and isinstance(exp, (int, float)):
                if nbf >= exp:
                    self.errors.append(
                        f"Incoherencia temporal: nbf ({nbf}) >= exp ({exp})"
                    )
        
        return result
    
    def _get_header_summary(self) -> Dict[str, Any]:
        """Genera resumen de validación del header"""
        header_symbols = self.symbol_table.get_by_scope('header')
        return {
            "fields_count": len(header_symbols),
            "standard_fields": [
                name for name, info in header_symbols.items() 
                if info['standard']
            ],
            "custom_fields": [
                name for name, info in header_symbols.items() 
                if not info['standard']
            ]
        }
    
    def _get_payload_summary(self) -> Dict[str, Any]:
        """Genera resumen de validación del payload"""
        payload_symbols = self.symbol_table.get_by_scope('payload')
        return {
            "claims_count": len(payload_symbols),
            "standard_claims": [
                name for name, info in payload_symbols.items() 
                if info['standard']
            ],
            "custom_claims": [
                name for name, info in payload_symbols.items() 
                if not info['standard']
            ]
        }