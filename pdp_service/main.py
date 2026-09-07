# pdp_service/main.py
import uvicorn
from fastapi import FastAPI
from shared.models import EvaluationRequest, PDPResponse
from shared.config import PORTS
from shared.event_logger import log_event
from pdp_service.rbac_engine import check_rbac_permissions, check_separation_of_duties
from pdp_service.abac_engine import evaluate_abac_policies, reload_policies

app = FastAPI(title="SecureCorp PDP Service")


@app.get("/health")
async def health():
    return {"status": "up"}


@app.post("/reload-policies", include_in_schema=False)
async def reload():
    reload_policies()
    return {"status": "policies reloaded"}

# Defines the main endpoint. It expects an EvaluationRequest payload fomr resource services and guarantees
#  the output matches the strict PDPResponse format.
@app.post("/evaluate", response_model=PDPResponse)
async def evaluate_request(req: EvaluationRequest):
    log_ctx = {
        "user": req.user.username,
        "resource": req.resource.service,
        "method": req.environment.method,
    }

    # Separation of Duties (SoD) Check
    # Checks if the user holds conflicting functional roles .
    if req.user.department == req.resource.department:
        sod_ok, sod_reason = check_separation_of_duties(req.user.functional_roles,req.environment.method)
        if not sod_ok:
            log_event("PDP", "SOD_VIOLATION", {**log_ctx, "reason": sod_reason}, "DENY")
            return PDPResponse(decision="DENY", reason=sod_reason, matched_policies=["SoD-Rule"], context={})

    # STEP 2: Role-Based Access Control (RBAC) Check
    # Checks if the user's primary job title grants them permission to use the requested HTTP method (action )
    rbac_ok, rbac_reason = check_rbac_permissions(req.user.role, req.environment.method)
    if not rbac_ok:
        log_event("PDP", "RBAC_DENIAL", {**log_ctx, "reason": rbac_reason}, "DENY")
        return PDPResponse(decision="DENY", reason=rbac_reason, matched_policies=["RBAC-Rule"], context={})
    
    #Attribute-Based Access Control (ABAC) Check
    req_data = req.model_dump()
    abac_decision, abac_reason, matched = evaluate_abac_policies(req_data)
    if abac_decision == "DENY":
        log_event("PDP", "ABAC_DENIAL", {**log_ctx, "policies": matched, "reason": abac_reason}, "DENY")
        return PDPResponse(decision="DENY", reason=abac_reason, matched_policies=matched, context={})

    # SUCCESS: If the request survives SoD, RBAC, and ABAC without triggering a single denial, access is officially granted.
    log_event("PDP", "ACCESS_GRANTED", log_ctx, "PERMIT")
    return PDPResponse(decision="PERMIT", reason="All RBAC and ABAC checks passed", matched_policies=[], context={})


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=PORTS["PDP"])
