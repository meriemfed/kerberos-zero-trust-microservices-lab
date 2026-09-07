# shared/event_logger.py
import logging
import json
import os
from datetime import datetime, timezone

# Dynamically find the root 'securecorp' folder to ensure all microservices write to the exact same central log file
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE_PATH = os.path.join(BASE_DIR, "audit_bus.log")

logger = logging.getLogger("ZeroTrustAuditBus")
logger.setLevel(logging.INFO)

# Ensure it doesn't add multiple handlers if imported multiple times
if not logger.handlers:
    file_handler = logging.FileHandler(LOG_FILE_PATH)
    file_handler.setLevel(logging.INFO)
    logger.addHandler(file_handler)

# Constructs a standardized, JSON-formatted audit record with a UTC timestamp and writes it to the log file.
def log_event(service: str, event_type: str, details: dict, status: str):
    
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": service,
        "event_type": event_type,
        "details": details,
        "status": status
    }
    logger.info(json.dumps(log_entry))