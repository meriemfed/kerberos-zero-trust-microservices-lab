# shared/crypto.py
import json
import time
import secrets
import base64
from typing import Any, Dict
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

# import the keys from config
from shared.config import SERVICE_KEYS, HMAC_SECRET


#HMAC (Hash-based Message Authentication Code) is a cryptographic algorithm that combines 
#a secret key with a hash function (SHA-256 here). It takes an input message and
#the secret key, processes them together, and outputs a fixed-length string of characters 
#called a hash or signature.
# used for integrity and authenticity

#AES-GCM is an authenticated, symmetric encryption algorithm.It uses the exact same secret 
#key to both encrypt and decrypt.While encrypting the data, it simultaneously calculates a 
#mathematical "Authentication Tag" that is appended to the ciphertext.

# ─── Encryption and HMAC ─── #

# encrypts plaintext using AES-GCM and generates an authentication tag. 
# it ensures data confidentiality and allows detection of tampering.
# used By: create_tgt, create_service_ticket, and build_authenticator to secure payloads.
def encrypt(plaintext: dict, key: bytes) -> Dict[str, str]:
    iv = secrets.token_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    json_data = json.dumps(plaintext).encode('utf-8')
    ciphertext, auth_tag = cipher.encrypt_and_digest(json_data)
    return {"iv": iv.hex(), "data": ciphertext.hex(), "authTag": auth_tag.hex()}

# decrypts ciphertext and verifies the AES-GCM authentication tag. 
#it extracts the original data while guaranteeing it was not tampered with.
# Used By: validate_ticket_structure and decrypt_authenticator to read secured payloads.
def decrypt(payload: Dict[str, str], key: bytes) -> dict:
    iv = bytes.fromhex(payload["iv"])
    data = bytes.fromhex(payload["data"])
    auth_tag = bytes.fromhex(payload["authTag"])
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    decrypted = cipher.decrypt_and_verify(data, auth_tag)
    return json.loads(decrypted.decode('utf-8'))

# vulnerable decrypt version that doesn't check auth tag 
"""def decrypt(payload: Dict[str, str], key: bytes) -> dict:
    iv = bytes.fromhex(payload["iv"])
    data = bytes.fromhex(payload["data"])
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    decrypted = cipher.decrypt(data)
    return json.loads(decrypted.decode('utf-8'))"""

# Generates an HMAC-SHA256 hash of the input data using a secret key. 
# Reason: Provides a cryptographic signature that proves data integrity and verifies the origin.
# Used By: create_tgt, create_service_ticket, build_authenticator, and internally by verify.
def sign(data: Dict[str, Any]) -> str:
    message = json.dumps(data, sort_keys=True).encode('utf-8')
    h = HMAC.new(HMAC_SECRET, msg=message, digestmod=SHA256)
    return h.hexdigest()

# Compares a provided signature against a newly calculated HMAC using a constant-time comparison. 
# Reason: Validates data integrity.
# Used By: validate_ticket_structure and decrypt_authenticator to check for tampering.
def verify(data: Dict[str, Any], signature: str) -> bool:
    expected = sign(data)
    return secrets.compare_digest(expected, signature)

# ─── Ticket Generation & Validation ─── #

# Encrypts and signs a payload using the KDC's key, outputting a Base64 string. 
# Reason: Issues the TGT to establish initial authentication.
# Used By: The Authentication Server (KDC) when a user first logs in successfully.
def create_tgt(payload: dict) -> str:
   
    encrypted = encrypt(payload, SERVICE_KEYS["identity-kdc"])
    encrypted["signature"] = sign(encrypted)
    ticket_bytes = json.dumps(encrypted).encode('utf-8')
    return base64.urlsafe_b64encode(ticket_bytes).decode('utf-8')

# Encrypts and signs a payload using a target service's specific key. 
# Reason: Issues a Service Ticket (ST) that authorizes a user to access a specific resource or API.
# Used By: The KDC when a client requests access to a microservice.
def create_service_ticket(payload: dict, target_service: str) -> str:
  
    key = SERVICE_KEYS.get(target_service)
    if not key:
        raise ValueError(f"Unknown service requested: {target_service}")

    encrypted = encrypt(payload, key)
    encrypted["signature"] = sign(encrypted)
    ticket_bytes = json.dumps(encrypted).encode('utf-8')
    return base64.urlsafe_b64encode(ticket_bytes).decode('utf-8')

# Decodes Base64, verifies the HMAC signature, and decrypts the AES payload. 
# Reason: Allows resource servers to authenticate incoming requests by verifying ticket validity and extracting claims.
# Used By: microservices and the KDC to validate incoming TGTs or Service Tickets.
def validate_ticket_structure(base64_ticket: str, decryption_key: bytes) -> dict:

    try:
        ticket_bytes = base64.urlsafe_b64decode(base64_ticket)
        ticket_copy = json.loads(ticket_bytes.decode('utf-8'))
    except Exception:
        raise ValueError("INVALID_TICKET_FORMAT")

    required = ["iv", "data", "authTag", "signature"]
    if not all(k in ticket_copy for k in required):
        raise ValueError("INVALID_TICKET_STRUCTURE")
########## vulnerable if commented allows ticket tampering attack signature not checked
    signature = ticket_copy.pop("signature")
    if not verify(ticket_copy, signature):
        raise ValueError("TICKET_TAMPERED")

    try:
        payload = decrypt(ticket_copy, decryption_key)
        return payload
    except Exception:
        raise ValueError("DECRYPTION_FAILED")

# ─── Authenticator ─── #

# Encrypts the username and current timestamp using a service session_key. 
# Reason: Proves the request is actively being made right now to prevent network replay attacks.
# Used By: The Client application immediately before sending an HTTP request(sent as header) to a resource server.
def build_authenticator(username: str, session_key: str) -> str:

    key = bytes.fromhex(session_key)  # hex string -> 16 raw bytes for AES

    payload = {
        "username": username,
        "timestamp": int(time.time()),
    }

    encrypted = encrypt(payload, key)
    encrypted["signature"] = sign(encrypted)

    auth_bytes = json.dumps(encrypted).encode('utf-8')
    return base64.urlsafe_b64encode(auth_bytes).decode('utf-8')


# Decodes, verifies, and decrypts the client's authenticator using the session key. 
# Reason: Extracts the timestamp so the server can evaluate it against the current time to ensure request freshness.
# Used By: The Resource Servers PEP upon receiving a client request.
def decrypt_authenticator(base64_authenticator: str, session_key: str) -> dict:

    try:
        auth_bytes = base64.urlsafe_b64decode(base64_authenticator)
        auth_copy = json.loads(auth_bytes.decode('utf-8'))
    except Exception:
        raise ValueError("INVALID_AUTHENTICATOR_FORMAT")

 
    required = ["iv", "data", "authTag", "signature"]
    if not all(k in auth_copy for k in required):
        raise ValueError("INVALID_AUTHENTICATOR_STRUCTURE")

    
    signature = auth_copy.pop("signature")
    if not verify(auth_copy, signature):
        raise ValueError("AUTHENTICATOR_TAMPERED")

    
    try:
        key = bytes.fromhex(session_key)
        payload = decrypt(auth_copy, key)
        return payload  
    except Exception:
        raise ValueError("AUTHENTICATOR_DECRYPTION_FAILED")