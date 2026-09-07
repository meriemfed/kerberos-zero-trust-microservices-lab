# pdp_service/abac_engine.py
import json
import os
import ipaddress

_POLICY_FILE = os.path.join(os.path.dirname(__file__), "policy_store.json")
# Creates an empty dictionary in the server's RAM to hold the loaded policies for fast access.
_policies_cache: dict = {}


# ── ABAC operator dispatch table ──────────────────────────────────────────────
# they execute the actual mathematical or string comparisons.Each function returns True when the deny condition IS triggered.


def _op_eq(actual, target, _req):
    if actual is None:
        return False
    return str(actual).lower() == str(target).lower()


def _op_neq(actual, target, _req):
    if actual is None:
        return False
    return str(actual).lower() != str(target).lower()


def _op_neq_field(actual, target, req):
    if actual is None:
        return False
    compare_value = _get_nested_value(req, target)
    if compare_value is None:
        return False
    return str(actual).lower() != str(compare_value).lower()


def _op_outside_range(actual, target, _req):
    if actual is None:
        return False
    if isinstance(target, list) and len(target) == 2:
        return not (target[0] <= actual <= target[1])
    return False

def _op_cidr_match(actual, target, _req):
    if actual is None:
        return False
    try:
        return ipaddress.ip_address(actual) in ipaddress.ip_network(target)
    except ValueError:
        return False


def _op_not_cidr_match(actual, target, _req):
    if actual is None:
        return False
    try:
        return ipaddress.ip_address(actual) not in ipaddress.ip_network(target)
    except ValueError:
        return False

_OPERATORS: dict = {
    "eq":            _op_eq,
    "neq":           _op_neq,
    "neq_field":     _op_neq_field,
    "outside_range": _op_outside_range,
    "cidr_match":     _op_cidr_match,
    "not_cidr_match": _op_not_cidr_match,
}


# Navigates through a nested dictionary using a dot-separated string path (e.g., "user.role").
# Reason: Allows the policy engine to dynamically extract exact attributes from complex JSON payloads.
def _get_nested_value(data: dict, path: str):
    keys = path.split(".")
    val = data
    for key in keys:
        if isinstance(val, dict) and key in val:
            val = val[key]
        else:
            return None
    return val


# Reads the policy_store.json file from the hard drive and loads it into the global RAM cache.
# Reason: Maximizes evaluation speed by eliminating disk I/O operations during active API requests.
def reload_policies() -> None:
    global _policies_cache
    if not os.path.exists(_POLICY_FILE):
        _policies_cache = {}
        return
    with open(_POLICY_FILE, "r") as f:
        _policies_cache = json.load(f)


# Processes the list of "Conditions" attached to a single policy statement.
# ALL conditions within the statement must return True for this to return True (AND logic).
def _evaluate_conditions(conditions: list, req_data: dict) -> bool:
    if not conditions:
        return False
    for cond in conditions:
        # Fetches the correct comparison function from the dispatch table based on the rule's Operator.
        handler = _OPERATORS.get(cond.get("Operator"))
        if handler is None:
            continue
        actual_value = _get_nested_value(req_data, cond.get("Field"))
        if not handler(actual_value, cond.get("Value"), req_data):
            return False
    return True

# The main entry point for the engine. It checks the incoming request against all cached statements.
def evaluate_abac_policies(req_data: dict) -> tuple[str, str, list]:
    statements = _policies_cache.get("PolicyDocument", {}).get("Statements", [])
    for statement in statements:
        #this engine is designed to process defined "Deny" policies only
        if statement.get("Effect") == "Deny":
            # If the specific conditions of this Deny statement are successfully met, access is instantly blocked.
            if _evaluate_conditions(statement.get("Conditions", []), req_data):
                return "DENY", statement.get("Description", "Blocked by ABAC"), [statement.get("Sid")]
    return "PERMIT", "All ABAC checks passed", []


# Warm cache at import time
reload_policies()
