# pdp_service/rbac_engine.py
import json
import os

_POLICY_FILE = os.path.join(os.path.dirname(__file__), "policy_store.json")

# reads central JSON policy file and extracts the roles permissions for rbac and toxic combinations for sod
def _load_rbac_config():
    with open(_POLICY_FILE) as f:
        doc = json.load(f)
    role_permissions = doc.get("RolePermissions", {})
    toxic_combinations = doc.get("ToxicCombinations", [])
    return role_permissions, toxic_combinations


ROLE_PERMISSIONS, TOXIC_COMBINATIONS = _load_rbac_config()

# check if actions of assigned user role allows him to do the requested action then block or allow access based on that
def check_rbac_permissions(role: str, method: str) -> tuple[bool, str]:
    allowed = ROLE_PERMISSIONS.get(role.lower(), [])
    if method.upper() in allowed:
        return True, f"Role '{role}' is authorized for {method}."
    return False, f"Insufficient RBAC permissions: Role '{role}' is not authorized for {method}."

# checks if toxic pair (we specified it) exist in functional roles of user,it blocks access 
def check_separation_of_duties(functional_roles: list, method: str) -> tuple[bool, str]:
    user_roles_set = set(functional_roles)
    for combo in TOXIC_COMBINATIONS:
            toxic_pair = set(combo["roles"])
            restricted_actions = combo.get("restricted_actions", [])
            if toxic_pair.issubset(user_roles_set) and method.upper() in restricted_actions:
                conflict = ", ".join(toxic_pair)
                return False, f"SoD Violation: Conflicting roles [{conflict}] cannot perform {method}"
    return True, "SoD checks passed."
