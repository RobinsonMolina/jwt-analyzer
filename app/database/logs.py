from datetime import datetime, timezone
from typing import Dict, Any, Optional
from app.database.db_config import get_database


async def save_analyze_log(
    token: str,
    secret: Optional[str],
    result: Dict[str, Any],
    execution_time_ms: int
) -> str:
    db = get_database()
    
    log_entry = {
        "action": "ANALYZE",
        "timestamp": datetime.now(timezone.utc),
        "token": token,
        "secret": secret,
        "result": result,
        "execution_time_ms": execution_time_ms
    }
    
    result = await db.logs.insert_one(log_entry)
    return str(result.inserted_id)


async def save_encode_log(
    payload: Dict[str, Any],
    secret: str,
    algorithm: str,
    expires_in: Optional[int],
    result: Dict[str, Any]
) -> str:
    db = get_database()
    
    log_entry = {
        "action": "ENCODE",
        "timestamp": datetime.now(timezone.utc),
        "payload": payload,
        "secret": secret,
        "algorithm": algorithm,
        "expires_in": expires_in,
        "result": {
            "success": result.get("valid", False),
            "token": result.get("token", "")
        }
    }
    
    result = await db.logs.insert_one(log_entry)
    return str(result.inserted_id)


async def get_all_logs(limit: int = 50) -> list:
    db = get_database()
    
    cursor = db.logs.find().sort("timestamp", -1).limit(limit)
    logs = await cursor.to_list(length=limit)
    
    # Convertir ObjectId a string para JSON
    for log in logs:
        log["_id"] = str(log["_id"])
    
    return logs