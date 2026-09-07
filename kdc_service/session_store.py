# kdc_service/session_store.py
import threading
import time
from shared.config import NONCE_TTL

_lock = threading.Lock()
_nonces: dict[str, float] = {}  
# Creates an empty dictionary in the server's RAM. 
# It will store the random string (nonce) as the key, and the exact time it was received as the value.

#Checks if a nonce has been used recently, while automatically deleting old ones.
# it Prevents network replay attacks by ensuring a login request packet can only be used exactly once.
def is_nonce_replayed(nonce: str) -> bool:
    
    now = time.time()
    with _lock:
        expired = [k for k, ts in _nonces.items() if now - ts > NONCE_TTL]
        for k in expired:
            del _nonces[k]
        if nonce in _nonces:
            return True
        _nonces[nonce] = now
        return False
