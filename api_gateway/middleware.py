# api_gateway/middleware.py

import os
import time
from collections import defaultdict

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from shared.event_logger import log_event


# Limits general traffic to 10 requests per 60-second rolling window.
RATE_LIMIT_REQUESTS = 10
RATE_LIMIT_WINDOW   = 60  # seconds

# Limits failed authentication/authorization attempts to 5 per 60-second window.
FAILURE_LIMIT       = 5
FAILURE_WINDOW      = 60  # seconds

REQUIRE_HTTPS = os.environ.get("REQUIRE_HTTPS", "false").lower() == "true"

# A whitelist of paths that do not count toward rate limits.
EXEMPT_PATHS = {"/docs", "/openapi.json", "/health", "/redoc"}


# defaultdict(list) automatically creates an empty list for an IP the very first time it connects, preventing KeyError crashes.
_request_log: dict[str, list[float]] = defaultdict(list)
_failure_log:  dict[str, list[float]] = defaultdict(list)




def _evict_old(timestamps: list[float], window: int) -> list[float]:
    """
    Removes timestamps from the list that are older than 
    their 60-second limit.
    """
    cutoff = time.time() - window
    return [t for t in timestamps if t > cutoff]


def record_failure(ip: str):
    
    _failure_log[ip] = _evict_old(_failure_log[ip], FAILURE_WINDOW)
    _failure_log[ip].append(time.time())


def is_failure_blocked(ip: str) -> bool:
    # Cleans up old failures, then checks if the remaining recent failures equal or exceed the limit.
    _failure_log[ip] = _evict_old(_failure_log[ip], FAILURE_WINDOW)
    return len(_failure_log[ip]) >= FAILURE_LIMIT


# The Active Middleware Class

class RateLimitMiddleware(BaseHTTPMiddleware):
    # The 'dispatch' function intercepts every single incoming request before the rest of the application sees it.
    async def dispatch(self, request: Request, call_next):
        
        # Extracts the raw IP address of the client making the request.
        ip = request.client.host

        # 1. Exemption Check
        # If the client is just asking for the /health status, let them through immediately without doing any math.
        if request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        # 2. Protocol Downgrade Defense
        if REQUIRE_HTTPS:
            # Reads the header injected by a reverse proxy to see what protocol the client actually used.
            proto = request.headers.get("x-forwarded-proto")
            # If the proxy reports the client connected via unencrypted HTTP, block it. 
            if proto and proto != "https":
                log_event("GATEWAY_FW", "TLS_DOWNGRADE_ATTEMPT", {"ip": ip, "path": request.url.path}, "BLOCKED")
                return JSONResponse(status_code=426, content={"detail": "Upgrade Required: HTTPS-only."})

        # 3. Brute Force Defense
        # Check if this IP is currently in the "penalty box" for too many 401/403 errors.
        if is_failure_blocked(ip):
            log_event("GATEWAY_FW", "BRUTE_FORCE_BLOCKED", {"ip": ip, "path": request.url.path}, "ALERT")
            return JSONResponse(status_code=429, content={"detail": "Too Many Requests: Brute force blocked."})

        # 4. Standard Rate Limit Defense
        # Clean up old general requests, then check if they have exceeded 10 requests in the last minute.
        _request_log[ip] = _evict_old(_request_log[ip], RATE_LIMIT_WINDOW)
        if len(_request_log[ip]) >= RATE_LIMIT_REQUESTS:
            log_event("GATEWAY_FW", "RATE_LIMIT_EXCEEDED", {"ip": ip, "path": request.url.path}, "WARNING")
            return JSONResponse(status_code=429, content={"detail": "Too Many Requests: Rate limit exceeded."})

       
        _request_log[ip].append(time.time())
        
        # 'call_next' hands the request over to the main application (the routing logic in main.py).
        response = await call_next(request)
        
       
        
        # Check if the internal service rejected the user.
        if response.status_code in (401, 403):
            # If so, record this as a failure against the IP address.
            record_failure(ip)
            
        # Return the final response to the client.
        return response