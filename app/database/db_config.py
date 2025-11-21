import os
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.server_api import ServerApi
from dotenv import load_dotenv

load_dotenv()

MONGODB_URL = os.getenv("MONGODB_URL")
DATABASE_NAME = os.getenv("DATABASE_NAME", "jwt_analyzer_db")


client = None
database = None


async def connect_to_mongo():
    """Conecta a MongoDB"""
    global client, database
    
    if not MONGODB_URL:
        raise ValueError("MONGODB_URL no está configurada en las variables de entorno")
    
    try:
        client = AsyncIOMotorClient(MONGODB_URL, server_api=ServerApi('1'))
        database = client[DATABASE_NAME]
        
        # Verificar conexión
        await client.admin.command('ping')
        print("==========Conexión a MongoDB establecida==========")
        
    except Exception as e:
        print(f"=======Error al conectar a MongoDB: {e}========")
        raise


async def close_mongo_connection():
    """Cierra la conexión a MongoDB"""
    global client
    if client:
        client.close()
        print("==========Conexión a MongoDB cerrada==========")


def get_database():
    """Retorna la instancia de la base de datos"""
    return database