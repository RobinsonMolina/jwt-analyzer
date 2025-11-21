"""
Utilidades para manejo de JSON
"""
import json
from typing import Dict, Any
from app.utils.errors import DecodingError


def parse_json(json_string: str) -> Dict[str, Any]:
    """
    Parsea una cadena JSON a diccionario
    
    Args:
        json_string: String en formato JSON
        
    Returns:
        Diccionario con los datos parseados
        
    Raises:
        DecodingError: Si el JSON es inválido
    """
    if not json_string:
        raise DecodingError("El string JSON está vacío")
    
    try:
        data = json.loads(json_string)
        
        # Verificar que sea un diccionario (objeto JSON)
        if not isinstance(data, dict):
            raise DecodingError(
                f"Se esperaba un objeto JSON, se encontró {type(data).__name__}"
            )
        
        return data
        
    except json.JSONDecodeError as e:
        raise DecodingError(
            f"JSON inválido: {str(e)} en línea {e.lineno}, columna {e.colno}"
        )
    except Exception as e:
        raise DecodingError(f"Error al parsear JSON: {str(e)}")


def to_json_string(data: Dict[str, Any], indent: int = None) -> str:
    """
    Convierte un diccionario a string JSON
    
    Args:
        data: Diccionario a convertir
        indent: Indentación (None para compacto)
        
    Returns:
        String JSON
        
    Raises:
        DecodingError: Si no se puede serializar
    """
    try:
        return json.dumps(data, indent=indent, ensure_ascii=False)
    except Exception as e:
        raise DecodingError(f"Error al serializar a JSON: {str(e)}")


def validate_json_structure(data: Dict[str, Any], required_fields: list = None) -> bool:
    """
    Valida que un diccionario tenga la estructura esperada
    
    Args:
        data: Diccionario a validar
        required_fields: Lista de campos requeridos
        
    Returns:
        True si es válido
        
    Raises:
        DecodingError: Si falta algún campo requerido
    """
    if not isinstance(data, dict):
        raise DecodingError("Los datos deben ser un diccionario")
    
    if required_fields:
        missing = [field for field in required_fields if field not in data]
        if missing:
            raise DecodingError(
                f"Campos requeridos faltantes: {', '.join(missing)}"
            )
    
    return True


def pretty_print_json(data: Dict[str, Any]) -> str:
    """
    Formatea JSON de forma legible
    
    Args:
        data: Diccionario a formatear
        
    Returns:
        String JSON formateado
    """
    return to_json_string(data, indent=2)