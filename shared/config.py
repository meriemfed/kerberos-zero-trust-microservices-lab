# shared/config.py
from dotenv import load_dotenv
load_dotenv()
import os
import warnings

# ─── HMAC Secret ─── #
# Loaded from the environment 
_hmac_raw = os.environ.get("HMAC_SECRET")
if not _hmac_raw:
    raise RuntimeError(
        "Missing required env var 'HMAC_SECRET'. Set it in your .env file before starting."
    )
HMAC_SECRET = _hmac_raw.encode("utf-8")[:32].ljust(32, b'\x00')

# ─── Services secret keys ─── #
# Each key is 32 bytes (AES-256).
_key_env_map = {
    "identity-kdc":     "KDC_SECRET_KEY",
    "resource-hr":      "HR_SECRET_KEY",
    "resource-finance": "FINANCE_SECRET_KEY",
    "resource-it":      "IT_SECRET_KEY",
    "resource-ops":     "OPS_SECRET_KEY",
}

SERVICE_KEYS: dict[str, bytes] = {}
for _svc, _env in _key_env_map.items():
    _raw = os.environ.get(_env)
    if not _raw:
        raise RuntimeError(
            f"Missing required env var '{_env}' for service '{_svc}'. "
            f"Set it in your .env file before starting."
        )
    SERVICE_KEYS[_svc] = _raw.encode("utf-8")[:32].ljust(32, b'\x00')

# ─── Time-To-Live (TTL) settings in seconds ─── #
TGT_TTL    = 60 * 60  # 1 hour
TICKET_TTL = 15 * 60  # 15 min
NONCE_TTL  = 5 * 60   # 5 min

# ─── dictionnary of every service and its port ─── #
PORTS = {
    "GATEWAY":         3000,
    "AUTH_SERVER":     3001,
    "PDP":             3006,
    "HR_SERVICE":      3011,
    "FINANCE_SERVICE": 3012,
    "IT_SERVICE":      3013,
    "OPS_SERVICE":     3014,
}


# Locally (no Docker): every service reaches others via "localhost".
# Inside Docker: containers reach each other by service name instead.
DOCKER_MODE = os.environ.get("DOCKER_MODE", "false").lower() == "true"

# Maps each service to the correct hostname
_SERVICE_NAMES = {
    "GATEWAY":         "gateway",
    "AUTH_SERVER":     "kdc",
    "PDP":             "pdp",
    "HR_SERVICE":      "hr",
    "FINANCE_SERVICE": "finance",
    "IT_SERVICE":      "it",
    "OPS_SERVICE":     "ops",
}

HOSTS = {
    key: (name if DOCKER_MODE else "localhost")
    for key, name in _SERVICE_NAMES.items()
}
