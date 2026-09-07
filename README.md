# SecureCorp: Kerberos-Style Zero Trust Microservices Lab


## 1. Executive Summary
This project implements a Kerberos-style authentication flow with Attribute-Based Access Control (ABAC), Role-Based Access Control (RBAC), and Separation of Duties (SoD). Every request is evaluated based on identity, environmental context (time, IP), and the principle of least privilege. it was built with FastAPI and a microservices architecture as a way to learn how a real microservices architecture is structured while implementing Kerberos properly.

## 2. Architectural Components

### 2.1 Identity Provider & KDC (Key Distribution Center)
- **Role:** The central Trust Engine.
- **Functions:** Authenticates users via password hashing, issues Ticket Granting Tickets (TGT), and manages Service Session Keys using AES-256 encryption.
- **Security:** Implements anti-replay mechanisms using nonces and timestamped authenticators.

### 2.2 API Gateway (The Policy Enforcement Point Entry Layer)
- **Role:** The single public entry point and network firewall.
- **Functions:**
  - Dynamic Routing: Forwards requests across the microservice ecosystem via a whitelisted path system .
  - Rate Limiting: Protects against brute-force and DoS attacks, with a separate stricter limit for repeated auth failures.
  - Context Enrichment: Captures the real client IP at the network layer and forwards it downstream via the `x-client-ip` header to the service that needs it.


### 2.3 PDP (Policy Decision Point)
- **Role:** The centralized "Brain" of the system — a dedicated service every resource server calls before granting access.
- **Evaluation Pipeline (in order):**
  1. **SoD (Separation of Duties):** Prevents toxic role combinations (e.g., `finance-approver` + `finance-auditor`) from performing conflicting actions. Scoped two ways: it only evaluates when the user is acting within their **own department** (cross-department requests are handled by ABAC's isolation policy instead), and it only blocks the **specific restricted actions** (e.g. `POST`/`DELETE`) tied to that toxic pair — a conflicted user can still read/view records.
  2. **RBAC:** Validates HTTP methods (`GET`, `POST`, `DELETE`) against the user's primary role.
  3. **ABAC Engine:** Executes a deny-overrides policy set against a JSON policy store, covering department isolation, classification-based clearance checks, working hours, and network-origin restrictions.

### 2.4 PEP (Policy Enforcement Point) — Resource Services
- **Role:** Each resource service (HR, Finance, IT, Ops) acts as its own PEP — validating tickets/authenticators, then querying the PDP before serving data.
- Shared logic lives in `shared/pep_factory.py`, avoiding duplicated security code across services.

### 2.5 SIEM Monitor
- **Role:** Real-time observability.
- **Functions:** Streams structured JSON logs from `audit_bus.log` to a color-coded terminal interface for live monitoring. Runs locally, outside the containerized services (see Section 6).

## 3. Microservices Overview
The architecture consists of independent services communicating over an internal network (or Docker's internal bridge network, when containerized):

| Service | Port | Description |
|---|---|---|
| API Gateway | 3000 | Entry point, rate limiting, and routing |
| Auth Server (KDC) | 3001 | TGT and Service Ticket issuance |
| PDP Service | 3006 | Centralized policy decision point (RBAC/ABAC/SoD) |
| HR Service | 3011 | HR records |
| Finance Service | 3012 | finance records |
| IT Service | 3013 | IT records |
| Ops Service | 3014 | Ops records |

## 4. Policy Framework (ABAC/RBAC/SoD)
The system enforces security via a structured `policy_store.json`:

- **Departmental Isolation:** Users can only access resources within their assigned department.
- **Working Hours:** Access is denied outside the 08:00–18:00 window.
- **Clearance-Based Classification:** "Secret" and "confidential" resources require matching user clearance.
- **Network Origin Restriction:** "secret" data requires the request to come from an internal IP range, checked server-side against the real captured IP
- **Action-Scoped Separation of Duties:** Toxic role combinations only block the specific actions defined as risky for that pair, not full department access.

## 5. Environment Configuration
Copy `.env.example` to `.env` and generate secure values:
python -c "import secrets; print(secrets.token_hex(32))"

Key variables:
- `HMAC_SECRET`, `*_SECRET_KEY` — required cryptographic keys, one per service.
- `REQUIRE_HTTPS` — off by default (local dev has no real HTTPS setup). In production, behind a reverse proxy doing TLS termination, it's on.
- `DEBUG_FAKE_IP` (optional, commented out by default) — lets you fake the detected client IP for testing the network-origin policy without needing a real VPN or second device. 
- `DOCKER_MODE` — set automatically by `docker-compose.yml`; controls whether services resolve each other via `localhost` (local dev) or container service names (Docker networking). 

## 6. Installation & Setup

### 6.1 Local (no Docker)

**Prerequisites:**
python -m venv venv
source venv/bin/activate # Windows: .\venv\Scripts\activate
pip install -r requirements.txt

**Running the framework:**
1. Launch services: `python run_all.py` (starts all 7 microservices)
2. Monitor traffic: in a separate terminal, `python monitor.py`
3. Client access: in another terminal, `python client.py`
4. Add test users: `python add_user.py` (creates local `users.json`)

### 6.2 Docker (containerized)

**Prerequisites:** Docker Desktop running.
docker compose up --build

This builds a single shared image (see `Dockerfile`) and starts all 7 backend services as separate containers on an internal bridge network, communicating via service names instead of `localhost`. `client.py` and `monitor.py` still run locally on the host (they're interactive tools, not backend services) and reach the gateway via its exposed port mapping.

To stop:
docker compose down


**Note:** running under Docker changes what IP the services actually see for incoming requests (Docker's bridge network gateway, not `127.0.0.1`), so the "secret data requires internal IP" policy will end up denying access even for legitimate local testing, unless you widen the allowed CIDR range in `policy_store.json` to include Docker's bridge subnet. I left this as it is on purpose.

## 7. Technical Stack
- **Backend:** Python 3.10+, FastAPI (asynchronous ASGI)
- **Communication:** HTTPX (asynchronous service-to-service requests)
- **Cryptography:** PyCryptodome (AES-GCM, SHA-256)
- **Logging:** Structured JSON audit logs, consumed by the SIEM monitor
- **Containerization:** Docker & Docker Compose (optional, see Section 6.2)