# shared/pep_factory.py
import ipaddress
import time
import os
from datetime import datetime
from typing import Callable
import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request
from shared.config import PORTS, SERVICE_KEYS, HOSTS
from shared.models import (
    AuthenticatorPayload, EnvironmentContext, EvaluationRequest,
    ResourceContext, UserContext,
)
from shared.crypto import decrypt_authenticator, validate_ticket_structure
from shared.event_logger import log_event
from shared.network import call_service

AUTHENTICATOR_TTL = 300  # 5 minutes


# this is used by every resources service to avoid duplication and cluttering main ressource files, instead 
# of writing the exact same security checks, error handling, and routing logic from scratch for every single
#  microservice
def create_pep_app(
    service_name: str,
    department: str,
    classification: str,
    get_records: Callable,
) -> FastAPI:
    app = FastAPI(title=f"SecureCorp {department.upper()} PEP")

    @app.get("/health")
    async def health():
        return {"status": "up", "service": service_name}
# this checks the service ticket and authenticator,used for Authentication
    async def _authorize(request: Request, authorization: str, x_authenticator: str) -> dict:

        # Make sure the client actually sent the required security headers.
        if not authorization or not authorization.startswith("Bearer "):
            log_event(service_name, "AUTH_MISSING", {"path": request.url.path}, "401")
            raise HTTPException(status_code=401, detail="Service Ticket Required")

        if not x_authenticator:
            log_event(service_name, "AUTHENTICATOR_MISSING", {"path": request.url.path}, "401")
            raise HTTPException(status_code=401, detail="Authenticator Required")
        
        # Open the Service Ticket using this specific service's private key.
        token = authorization.split(" ")[1]
        claims = validate_ticket_structure(token, SERVICE_KEYS[service_name])
        now = int(time.time())

        #Check if the Service Ticket itself has expired.
        if now > claims["expires_at"]:
            log_event(service_name, "TICKET_EXPIRED", {"user": claims.get("sub")}, "DENIED")
            raise HTTPException(status_code=401, detail="Service Ticket Expired")

        session_key = claims.get("session_key")
        if not session_key:
            raise ValueError("Ticket missing session_key")

        # Open the Authenticator using the session key found inside the ticket.
        auth_data = decrypt_authenticator(x_authenticator, session_key)
        # Loads the decrypted data into a Pydantic model to enforce strict data types
        authenticator = AuthenticatorPayload(**auth_data)

        # Verify the ticket and the authenticator belong to the exact same person.
        if authenticator.username != claims["sub"]:
            log_event(service_name, "AUTHENTICATOR_MISMATCH",
                      {"ticket_user": claims["sub"], "auth_user": authenticator.username}, "DENIED")
            raise HTTPException(status_code=401, detail="Authenticator username mismatch")

        # Verify the timestamp is fresh to block network replay attacks.
        if abs(now - authenticator.timestamp) > AUTHENTICATOR_TTL:
            log_event(service_name, "AUTHENTICATOR_EXPIRED",
                      {"user": claims["sub"], "age": now - authenticator.timestamp}, "DENIED")
            raise HTTPException(status_code=401, detail="Authenticator expired")

        log_event(service_name, "AUTHENTICATOR_OK", {"user": claims["sub"]}, "SUCCESS")
        return claims

    async def _call_pdp(request: Request, claims: dict, record_classification: str = None) -> dict:
        
        # it collects user info,resource info and environment info and sends this package to the PDP over the network to ask for permission.
        pdp_req = EvaluationRequest(
            user=UserContext(
                username=claims["sub"],
                role=claims["role"],
                department=claims["department"],
                clearance=claims["clearance"],
                functional_roles=claims.get("functional_roles", []),
            ),
            resource=ResourceContext(
                service=service_name,
                department=department,
                classification=record_classification if record_classification else classification,
            ),
            environment=EnvironmentContext(
                method=request.method,
               # time=datetime.now().hour, # use number between 0 and 23
                time=12, 
                location="internal",
                ip_address=os.environ.get("DEBUG_FAKE_IP") or request.headers.get("x-client-ip", request.client.host),
            ),
        )
       # print(f"[DEBUG] ip_address captured: {pdp_req.environment.ip_address}")
        # converts the Pydantic model to a standard dict and sends it via HTTP POST to the PDP service.
        pdp_resp = await call_service(
            host=HOSTS["PDP"], port=PORTS["PDP"], path="/evaluate", method="POST",
            body=pdp_req.model_dump()
        )

        body = pdp_resp.get("body")
        # Checks if the network request failed or returned empty data.
        if pdp_resp.get("status") == 503 or body is None:
            raise HTTPException(status_code=503, detail="Authorization service unavailable")
        # Returns the PDP's decision (Allow/Deny and matched policies).
        return body
    # defines an API endpoint that handles listing general records. Accepts GET, POST, and DELETE methods.
    @app.api_route("/records", methods=["GET", "POST", "DELETE"])
    async def handle_records(
        request: Request,
        authorization: str = Header(None),
        x_authenticator: str = Header(None),
    ):
        try:
            #  Auth
            claims = await _authorize(request, authorization, x_authenticator)

            # PDP with service classification(all public by default to be able to view record list only)
            pdp_body = await _call_pdp(request, claims,record_classification="public")

            # Checks if the central policy engine explicitly allowed the action.
            if pdp_body.get("decision") == "PERMIT":
                all_records = get_records()
                # Loops through the database results and creates a new list containing only IDs and Names, hiding sensitive fields.
                summary = [{"id": r["id"], "name": r.get("name") or r.get("item") or r.get("asset") or r.get("task")} for r in all_records]
                log_event(service_name, "LIST_GRANTED", {"user": claims["sub"]}, "SUCCESS")
                return {"status": "Authorized", "records": summary}
            # If the decision was not "PERMIT", extracts the reason and throws a 403 Forbidden HTTP error.
            reason = pdp_body.get("reason", "Policy Violation")
            log_event(service_name, "ACCESS_DENIED", {"user": claims["sub"], "reason": reason}, "DENY")
            raise HTTPException(status_code=403, detail=f"Access Denied: {reason}")

        except HTTPException:
            raise
        except ValueError as e:
            log_event(service_name, "TICKET_ERROR", {"error": str(e)}, "DENIED")
            raise HTTPException(status_code=401, detail="Invalid Security Ticket")
        except Exception as e:
            log_event(service_name, "ERROR", {"error": str(e)}, "FAILURE")
            raise HTTPException(status_code=500, detail="Internal server error")
    # Defines an API endpoint for accessing a specific record based on its unique integer ID in the URL.
    @app.api_route("/records/{record_id}", methods=["GET", "POST", "DELETE"])
    async def handle_record_by_id(
        record_id: int,
        request: Request,
        authorization: str = Header(None),
        x_authenticator: str = Header(None),
    ):
        try:
            #  Auth
            claims = await _authorize(request, authorization, x_authenticator)

            # Fetches all records the user's clearance level is allowed to see from the db.
            visible_records = get_records()
            # Scans the list to find where 'id' matches the requested URL parameter.
            record = next((r for r in visible_records if r.get("id") == record_id), None)
            # If the database returns nothing, or the ID does not exist, throw a 404 Not Found error.
            if record is None:
                log_event(service_name, "RECORD_NOT_FOUND",
                          {"user": claims["sub"], "record_id": record_id,
                           "clearance": claims["clearance"]}, "404")
                raise HTTPException(
                    status_code=404,
                    detail=f"Record {record_id} not found or not accessible"
                )

            # Reads the specific 'classification' field from the requested record.
            record_classification = record.get("classification", classification)
            # Asks the PDP if the user has permission to access this specific data classification.
            pdp_body = await _call_pdp(request, claims, record_classification=record_classification)
            # If the PDP rejects the request, blocks access and throws a 403 Forbidden error.
            if pdp_body.get("decision") != "PERMIT":
                reason = pdp_body.get("reason", "Policy Violation")
                log_event(service_name, "ACCESS_DENIED",
                          {"user": claims["sub"], "reason": reason, "record_id": record_id,
                           "classification": record_classification}, "DENY")
                raise HTTPException(status_code=403, detail=f"Access Denied: {reason}")

            # # If permitted returns the record with details
            log_event(service_name, "RECORD_ACCESSED",
                      {"user": claims["sub"], "record_id": record_id,
                       "classification": record_classification}, "SUCCESS")
            return {"status": "Authorized", "data": record}

        except HTTPException:
            raise
        except ValueError as e:
            log_event(service_name, "TICKET_ERROR", {"error": str(e)}, "DENIED")
            raise HTTPException(status_code=401, detail="Invalid Security Ticket")
        except Exception as e:
            log_event(service_name, "ERROR", {"error": str(e)}, "FAILURE")
            raise HTTPException(status_code=500, detail="Internal server error")

    return app