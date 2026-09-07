# api_gateway/main.py
import uvicorn
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from shared.config import PORTS, HOSTS
from shared.event_logger import log_event
from api_gateway.middleware import RateLimitMiddleware

app = FastAPI(title="SecureCorp API Gateway")
app.add_middleware(RateLimitMiddleware)

ROUTES = {
    "auth":    {"host": HOSTS["AUTH_SERVER"],     "port": PORTS["AUTH_SERVER"]},
    "hr":      {"host": HOSTS["HR_SERVICE"],      "port": PORTS["HR_SERVICE"]},
    "finance": {"host": HOSTS["FINANCE_SERVICE"], "port": PORTS["FINANCE_SERVICE"]},
    "it":      {"host": HOSTS["IT_SERVICE"],      "port": PORTS["IT_SERVICE"]},
    "ops":     {"host": HOSTS["OPS_SERVICE"],     "port": PORTS["OPS_SERVICE"]},
}

# Whitelist of allowed paths per service -- prevents SSRF and path traversal.
ALLOWED_PATHS: dict[str, set[str]] = {
    "auth":    {"login", "request-ticket", "health"},
    "hr":      {"records", "health"},
    "finance": {"records", "health"},
    "it":      {"records", "health"},
    "ops":     {"records", "health"},
}

# Singleton httpx client -- connection pool reused across all forwarded requests.
_client = httpx.AsyncClient(timeout=10.0)


@app.get("/health")
async def health():
    return {"status": "up", "service": "api-gateway"}


# This single route catches ALL traffic using dynamic variables. 
# {service} catches the first part of the URL .
# {path:path} catches everything else after it
@app.api_route("/{service}/{path:path}", methods=["GET", "POST", "DELETE"])
async def universal_forwarder(service: str, path: str, request: Request):
    if service not in ROUTES:
        raise HTTPException(status_code=404, detail=f"Service '{service}' not found")

    """clean_path = path.split("?")[0].strip("/")
    if clean_path not in ALLOWED_PATHS.get(service, set()):
        raise HTTPException(status_code=404, detail=f"Path '/{path}' not found in service '{service}'")"""
    clean_path = path.split("?")[0].strip("/")
    base_path = clean_path.split("/")[0]  # prend seulement "records" depuis "records/1"
    if base_path not in ALLOWED_PATHS.get(service, set()):
        raise HTTPException(status_code=404, detail=f"Path '/{path}' not found in service '{service}'")

    url = f"http://{ROUTES[service]['host']}:{ROUTES[service]['port']}/{path}"

    headers = {}
    for key in ("authorization", "x-authenticator", "content-type"):
        val = request.headers.get(key)
        if val:
            headers[key] = val

    # Forward the real client IP to the downstream service
    headers["x-client-ip"] = request.client.host

    log_event("GATEWAY", "FORWARD", {
        "method": request.method,
        "service": service,
        "url": url,
    }, "ROUTING")

    try:
        body = await request.body()
        resp = await _client.request(
            method=request.method,
            url=url,
            headers=headers,
            content=body,
        )
        return JSONResponse(status_code=resp.status_code, content=resp.json())
    except httpx.RequestError as e:
        log_event("GATEWAY", "FORWARD_ERROR", {"error": str(e)}, "FAILURE")
        raise HTTPException(status_code=503, detail="Backend Service Unavailable")
    except Exception as e:
        log_event("GATEWAY", "INTERNAL_ERROR", {"error": str(e)}, "FAILURE")
        raise HTTPException(status_code=500, detail="Internal Gateway Error")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORTS["GATEWAY"])
