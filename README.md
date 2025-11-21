# JWT Analyzer - Backend API

API RESTful para análisis completo de JSON Web Tokens implementando todas las fases de lenguajes formales.

## Descripción

Backend desarrollado con FastAPI que implementa un analizador completo de JWT aplicando conceptos de teoría de compiladores y lenguajes formales. Ejecuta seis fases de análisis sobre cada token JWT.

## Fases Implementadas

### 1. Análisis Léxico (`services/lexer.py`)
- Tokenización del JWT en componentes (HEADER, PAYLOAD, SIGNATURE)
- Validación del alfabeto Base64URL (A-Z, a-z, 0-9, -, _)
- Identificación de delimitadores (.)
- Detección de caracteres inválidos

### 2. Análisis Sintáctico (`services/parser.py`)
- Validación de gramática libre de contexto
- Gramática: `JWT → HEADER '.' PAYLOAD '.' SIGNATURE`
- Parser descendente recursivo
- Generación de árbol de derivación

### 3. Análisis Semántico (`services/semantic.py`)
- Tabla de símbolos con todos los claims
- Validación de tipos de datos
- Verificación de campos obligatorios (alg, typ)
- Validación temporal (exp, iat, nbf)
- Detección de tokens expirados

### 4. Decodificación (`services/jwt_decoder.py`)
- Decodificación Base64URL a bytes
- Parsing de JSON (header y payload)
- Extracción de claims estándar y personalizados
- Manejo de errores de formato

### 5. Codificación (`services/jwt_encoder.py`)
- Generación de JWT desde objetos JSON
- Serialización y codificación Base64URL
- Firma criptográfica HMAC (HS256, HS384, HS512)
- Generación automática de timestamps

### 6. Verificación Criptográfica (`services/verifier.py`)
- Validación de firmas digitales
- Detección de tokens manipulados
- Comparación timing-safe de firmas
- Soporte para múltiples algoritmos

## Arquitectura
```
backend/
├── app/
│   ├── main.py              # Punto de entrada FastAPI
│   ├── api/
│   │   └── routes_jwt.py    # Endpoints REST
│   ├── services/            # Fases del analizador
│   ├── models/              # Modelos Pydantic
│   ├── utils/               # Utilidades (Base64URL, JSON, errores)
│   ├── database/            # MongoDB config y logs
│   └── core/                # Configuración
├── tests/                   # Tests unitarios
└── requirements.txt         # Dependencias
```

## Instalación

### Requisitos
- Python 3.14+
- MongoDB Atlas (cuenta gratuita)

### Configuración

1. **Instalar dependencias**
```bash
pip install -r requirements.txt
```

2. **Ejecutar servidor**
```bash
python -m uvicorn app.main:app --reload
```

Servidor: `http://localhost:8000`  
Documentación: `http://localhost:8000/docs`

## Endpoints API

### Análisis completo
```http
POST /api/v1/analyze
{
  "token": "eyJhbGc...",
  "secret": "my-secret-key"
}
```

### Codificar JWT
```http
POST /api/v1/encode
{
  "payload": {"sub": "user123"},
  "secret": "my-secret-key",
  "algorithm": "HS256",
  "expires_in": 3600
}
```

### Decodificar JWT
```http
POST /api/v1/decode
{
  "token": "eyJhbGc..."
}
```

### Verificar firma
```http
POST /api/v1/verify
{
  "token": "eyJhbGc...",
  "secret": "my-secret-key"
}
```

### Ver logs
```http
GET /api/v1/logs?limit=50
```

## Tests
```bash
python tests/test_lexer.py
python tests/test_parser.py
python tests/test_semantic.py
python tests/test_decoder.py
python tests/test_encoder.py
python tests/test_verifier.py
```

## Tecnologías

- **FastAPI 0.104.1** - Framework web asíncrono
- **Pydantic 2.5.0** - Validación de datos
- **Motor 3.7.1** - Driver async de MongoDB
- **Cryptography 41.0.7** - Operaciones criptográficas
- **Pytest 7.4.3** - Testing

## Conceptos de Lenguajes Formales

- **Alfabeto**: Base64URL = {A-Z, a-z, 0-9, -, _}
- **Gramática**: GLC para estructura JWT
- **Autómata**: Reconocimiento de tokens
- **Tabla de Símbolos**: Claims con tipo y alcance
- **Derivación**: Árbol sintáctico
- **Análisis en Cascada**: Fases secuenciales con detención temprana