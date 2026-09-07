# kdc_service/main.py

from fastapi import FastAPI, HTTPException
import secrets
import time

import uvicorn

from shared.config import PORTS, SERVICE_KEYS, TGT_TTL, TICKET_TTL
from shared.models import LoginRequest, TicketRequest

from shared.crypto import create_tgt, create_service_ticket, validate_ticket_structure
from shared.event_logger import log_event
from kdc_service.user_directory import authenticate_user
from kdc_service.session_store import is_nonce_replayed

app = FastAPI(title="SecureCorp KDC")

@app.get("/health")
async def health():

    return {"status": "up"}

# Authentication & TGT Issuance 
@app.post("/login")
async def login(req: LoginRequest):
    
    # validates the username and password against the PBKDF2 hashes in the database.
    attributes = authenticate_user(req.username, req.password)
    
    if not attributes:
        log_event("KDC", "AUTH_FAILURE", {"user": req.username}, "DENIED")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generates a 256-bit (32 bytes) random hex string to act as the temporary AES encryption key for the user's session.
    client_session_key = secrets.token_hex(32)  
    now = int(time.time())
    
    # creates the tgt 
    tgt_payload = {
        "typ":            "TGT",
        "sub":            req.username,
        "username":       req.username,
        
        # Embeds user's attributes for pdp later
        "role":           attributes.get("role"),
        "department":     attributes.get("department"),
        "clearance":      attributes.get("clearance"),
        "functional_roles": attributes.get("functional_roles", []),
        
        # Sets time limits to enforce ticket expiration.
        "issued_at":      now,
        "expires_at":     now + TGT_TTL,
        
        # Adds a random one-time string (nonce) to prevent attackers from replay attacks.
        "nonce":          secrets.token_hex(16),
        
        # Specifies that this ticket is only valid for communicating back to the KDC itself.
        "tgs_audience":   "identity-kdc",
        
        # Embeds the temporary session key so the KDC can extract it later to decrypt the user's Authenticators.
        "session_key":    client_session_key,
    }

    # Cryptographically signs and encrypts the payload using the KDC's master private key.
    tgt = create_tgt(tgt_payload)
    
    log_event("KDC", "TGT_ISSUED", {"user": req.username}, "SUCCESS")
    
    # Returns the encrypted TGT (which the client stores) and the raw session key (which the client uses for encryption).
    return {"tgt": tgt, "client_session_key": client_session_key, "expires_at": now + TGT_TTL}

# Service Ticket Issuance

@app.post("/request-ticket")
async def get_service_ticket(req: TicketRequest):
   
    try:
        tgt_payload = validate_ticket_structure(req.tgt, SERVICE_KEYS["identity-kdc"])

        now = int(time.time())
        if now > tgt_payload["expires_at"]:
            raise HTTPException(status_code=401, detail="TGT expired")

        # Replay key = request_nonce (unique per call) instead of tgt nonce
        replay_key = req.request_nonce or tgt_payload["nonce"]
        ###### vulnerbale to reply attack if commented
        if is_nonce_replayed(replay_key):
            log_event("KDC", "REPLAY_ATTACK", {"nonce": replay_key}, "DENIED")
            raise HTTPException(status_code=403, detail="REPLAY_ATTACK_DETECTED")

        # Generates a brand new 256-bit AES key strictly for communication between the client and the target resource (e.g., the Finance API).
        service_session_key = secrets.token_hex(32)  
        now = int(time.time())
        
        # Constructs the internal payload for the new Service Ticket.
        st_payload = {
            "typ":            "ST",
            "sub":            tgt_payload["sub"],
            "service":        req.service,
            "role":           tgt_payload["role"],
            "department":     tgt_payload["department"],
            "clearance":      tgt_payload.get("clearance"),
            "functional_roles": tgt_payload.get("functional_roles", []),
            # Resets the timestamps for this specific Service Ticket.
            "issued_at":      now,
            "expires_at":     now + TICKET_TTL,
            "nonce":          secrets.token_hex(16),
            "session_key":    service_session_key,
        }

        # Encrypts the Service Ticket using the private key belonging to the requested target service. 
        st = create_service_ticket(st_payload, req.service)
        
        log_event("KDC", "ST_ISSUED", {"user": tgt_payload["username"], "service": req.service}, "SUCCESS")
        
        # Returns the target-encrypted Service Ticket and the service session key back to the client.
        return {"service_ticket": st, "service_session_key": service_session_key}

    except HTTPException:
        raise
    except Exception as e:
        
        log_event("KDC", "ERROR", {"detail": str(e)}, "FAILURE")
        raise HTTPException(status_code=401, detail="Authentication failed")


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=PORTS["AUTH_SERVER"])