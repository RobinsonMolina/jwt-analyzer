import os
from typing import List

class Settings:
    # API Config
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "JWT Analyzer"
    VERSION: str = "1.0.0"
    
    # CORS
    BACKEND_CORS_ORIGINS = os.getenv("CORS_ORIGINS", "").split(",")
    
    # JWT Config
    DEFAULT_ALGORITHM: str = "HS256"
    SUPPORTED_ALGORITHMS: List[str] = ["HS256", "HS384", "HS512"]

settings = Settings()