# shared/network.py
import httpx
from typing import Any, Dict

# reusable singleton client — connection pool reused across all inter-service calls.instead 
# of making new connection each time
_client = httpx.AsyncClient(timeout=10.0)

#used by Any microservice that needs to talk to another microservice
async def call_service(host: str,port: int, path: str, method: str = "GET", body: Any = None) -> Dict[str, Any]:
    """Asynchronous HTTP helper for internal microservice communication."""
    url = f"http://{host}:{port}{path}"
    try:
        if method.upper() == "GET":
            response = await _client.get(url, params=body)
        else:
            response = await _client.request(method, url, json=body)
        return {"status": response.status_code, "body": response.json()}
    except Exception as e:
        return {"status": 503, "body": {"error": "Service Unavailable", "details": str(e)}}
    

