# shared/models.py


from pydantic import BaseModel, Field

from typing import List, Dict, Any, Optional

# Validates incoming username and password formats during initial authentication.
# Reason: Ensures credentials meet minimum security criteria (e.g., password length, valid username characters) before querying the database.
# Used By: Identity-KDC Service (Login API endpoint).
class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_.\-]+$")
    password: str = Field(min_length=8)

# Validates requests asking for a new Service Ticket.
# Reason: Ensures the client provides both their master TGT and the exact name of the target service they want to access.
# Used By: Identity-KDC Service (Ticket Granting API endpoint).
class TicketRequest(BaseModel):
    tgt: str
    service: str
    request_nonce: str = "" 

# Defines the generic structure for an access control query.
# Reason: Standardizes how components package attributes when checking if a specific action is permitted.
# Used By: Resource Servers / Policy Enforcement Points (PEP) when structuring data.
class AccessRequest(BaseModel):
    user_attributes: Dict[str, Any]
    resource_attributes: Dict[str, Any]
    action: str

# Structures the user's identity, Role-Based (RBAC), and Attribute-Based (ABAC) data.
# Reason: Provides the authorization engine with the user's specific permissions, department, and clearance levels.
# Used By: Policy Decision Point (PDP) during policy evaluation.
class UserContext(BaseModel):
    username: str
    role: str
    department: str
    clearance: str
    functional_roles: List[str] = Field(default_factory=list)

# Structures the target resource's specific attributes.
# Reason: Provides the authorization engine with the sensitivity and departmental ownership of the requested data.
# Used By: Policy Decision Point (PDP) during policy evaluation.
class ResourceContext(BaseModel):
    service: str
    department: str
    classification: str

# Structures the environmental conditions of the HTTP request (time, location, method).
# Reason: Enables dynamic ABAC policies, such as blocking access attempts that occur outside of standard business hours.
# Used By: Policy Decision Point (PDP) during policy evaluation.
class EnvironmentContext(BaseModel):
    method: str
    time: int   
    location: str   
    ip_address: str 

# Aggregates the user, resource, and environment contexts into a single payload.
# Reason: Forms the complete, structured authorization question sent over the network to the central policy engine.
# Used By: Resource Servers (PEP) to ask the Policy Decision Point (PDP) for an access decision.
class EvaluationRequest(BaseModel):
    user: UserContext
    resource: ResourceContext
    environment: EnvironmentContext

# Structures the final allow/deny decision and the reasons behind it.
# Reason: Standardizes the authorization reply so the requesting service programmatically knows whether to block or allow the user.
# Used By: Policy Decision Point (PDP) to reply to Resource Servers (PEP).
class PDPResponse(BaseModel):
    decision: str
    reason: str
    matched_policies: List[str]
    context: Dict[str, Any]

# Defines the expected internal structure of a decrypted client authenticator.
# Reason: Ensures the decrypted Kerberos JSON maps correctly to a username and timestamp for replay attack prevention.
# Used By: Resource Servers (PEP) after running the decrypt_authenticator function on the X-Authenticator header.
class AuthenticatorPayload(BaseModel):
    username: str
    timestamp: int