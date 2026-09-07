# client.py
import asyncio
import getpass
import httpx
import json
import sys
import os
from shared.crypto import build_authenticator

GATEWAY = "http://localhost:3000"
SERVICES = ["finance", "hr", "it", "ops"]

# ─── Colors ───────────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def banner():
    print(f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════╗
║          SecureCorp Zero-Trust CLI           ║
║      Kerberos + RBAC/ABAC Access Control     ║
╚══════════════════════════════════════════════╝
{RESET}""")

def print_step(n: int, msg: str):
    print(f"\n{CYAN}{BOLD}[Step {n}]{RESET} {msg}")

def print_ok(msg: str):
    print(f"  {GREEN}✓{RESET} {msg}")

def print_err(msg: str):
    print(f"  {RED}✗{RESET} {msg}")

def pick_service() -> str:
    print(f"\n{BOLD}Available services:{RESET}")
    for i, s in enumerate(SERVICES, 1):
        print(f"  [{i}] {s}")
    while True:
        choice = input(f"\n{BOLD}Select service (1-{len(SERVICES)}): {RESET}").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(SERVICES):
            return SERVICES[int(choice) - 1]
        print_err("Invalid choice.")

def pick_action() -> str:
    print(f"\n{BOLD}Available Actions:{RESET}")
    print("  [1] READ   (GET)")
    print("  [2] CREATE (POST)")
    print("  [3] DELETE (DELETE)")
    while True:
        choice = input(f"\n{BOLD}Select action (1-3): {RESET}").strip()
        if choice == "1": return "GET"
        if choice == "2": return "POST"
        if choice == "3": return "DELETE"
        print_err("Invalid choice.")

async def login(client: httpx.AsyncClient) -> tuple[str, str]:
    print_step(1, "Authentication — Login to KDC")
    username = input(f"  {BOLD}Username: {RESET}").strip()
    password = getpass.getpass("  Password: ")

    resp = await client.post(f"{GATEWAY}/auth/login", json={
        "username": username,
        "password": password
    })

    if resp.status_code != 200:
        detail = resp.json().get("detail", "Unknown error")
        print_err(f"Login failed: {detail}")
        sys.exit(1)

    data = resp.json()
    print_ok(f"Logged in as '{username}'")
    print_ok(f"TGT received (expires at {data['expires_at']})")
    return username, data["tgt"]

async def request_ticket(client: httpx.AsyncClient, tgt: str, service: str) -> tuple[str, str]:
    print_step(2, f"Ticket Granting — Requesting ST for '{service}'")

    resp = await client.post(f"{GATEWAY}/auth/request-ticket", json={
        "tgt": tgt,
        "service": f"resource-{service}",
        "request_nonce": os.urandom(16).hex()
    })

    if resp.status_code != 200:
        detail = resp.json().get("detail", "Unknown error")
        print_err(f"Ticket request failed: {detail}")
        sys.exit(1)

    data = resp.json()
    print_ok(f"Service ticket received for 'resource-{service}'")
    return data["service_ticket"], data["service_session_key"]

def make_authenticator(username: str, session_key: str) -> str:
    print_step(3, "Authenticator — Proving possession of session key")
    auth = build_authenticator(username, session_key)
    print_ok("Authenticator built and encrypted with session key")
    return auth

async def call_list(
    client: httpx.AsyncClient,
    service: str,
    ticket: str,
    authenticator: str,
    method: str,
) -> tuple[int, dict]:
    """Call GET /records → summary list."""
    print_step(4, f"Resource Access — Calling {method} /{service}/records")

    resp = await client.request(
        method=method,
        url=f"{GATEWAY}/{service}/records",
        headers={
            "Authorization": f"Bearer {ticket}",
            "x-authenticator": authenticator
        }
    )

    try:
        return resp.status_code, resp.json()
    except json.JSONDecodeError:
        print(f"\n{RED}{BOLD}🚨 CRITICAL BACKEND CRASH 🚨{RESET}")
        print(f"HTTP Status: {resp.status_code}")
        print(f"Raw Response: {resp.text}\n")
        sys.exit(1)

async def call_record(
    client: httpx.AsyncClient,
    service: str,
    ticket: str,
    authenticator: str,
    method: str,
    record_id: str,
) -> tuple[int, dict]:
    """Call GET /records/{id} → full detail."""
    print_step(4, f"Resource Access — Calling {method} /{service}/records/{record_id}")

    resp = await client.request(
        method=method,
        url=f"{GATEWAY}/{service}/records/{record_id}",
        headers={
            "Authorization": f"Bearer {ticket}",
            "x-authenticator": authenticator
        }
    )

    try:
        return resp.status_code, resp.json()
    except json.JSONDecodeError:
        print(f"\n{RED}{BOLD}🚨 CRITICAL BACKEND CRASH 🚨{RESET}")
        print(f"HTTP Status: {resp.status_code}")
        print(f"Raw Response: {resp.text}\n")
        sys.exit(1)

def display_list(body: dict) -> str | None:
    """Display summary list and return chosen id."""
    records = body.get("records", [])
    if not records:
        print(f"\n  {YELLOW}(No records found){RESET}")
        return None

    print(f"\n{CYAN}{BOLD}{'─' * 48}{RESET}")
    print(f"{GREEN}{BOLD}   RECORDS LIST{RESET}")
    print(f"{CYAN}{BOLD}{'─' * 48}{RESET}\n")

    valid_ids = [str(r["id"]) for r in records]
    for r in records:
        print(f"  [{r['id']}] {BOLD}{r['name']}{RESET}")

    print()
    while True:
        choice = input(f"{BOLD}Select record ID or 0 to quit: {RESET}").strip()
        if choice == "0":
            return None
        if choice in valid_ids:
            return choice
        print_err(f"Invalid ID. Choose from: {', '.join(valid_ids)}")

def display_result(status: int, body: dict):
    """Display full record detail."""
    print(f"\n{CYAN}{BOLD}{'─' * 48}{RESET}")

    if status == 200:
        print(f"{GREEN}{BOLD}   ACCESS GRANTED{RESET}")
        print(f"{CYAN}{BOLD}{'─' * 48}{RESET}\n")

        record = body.get("data")
        if not record:
            print(f"  {YELLOW}(No data found){RESET}")
        else:
            title = (
                record.get("name") or
                record.get("item") or
                record.get("asset") or
                record.get("task") or
                f"Record ID: {record.get('id', '?')}"
            )
            print(f"  {BOLD}{title}{RESET}\n")
            skip = {"name", "item", "asset", "task"}
            for k, v in record.items():
                if k not in skip:
                    print(f"    {CYAN}{k}{RESET}: {v}")
            print()
    else:
        print(f"{RED}{BOLD}   ACCESS DENIED{RESET}")
        print(f"{CYAN}{BOLD}{'─' * 48}{RESET}\n")
        print_err(body.get("detail", "Unknown error"))

    print(f"{CYAN}{BOLD}{'─' * 48}{RESET}\n")

async def main():
    banner()

    while True:  # outer loop = one iteration per logged-in user
        async with httpx.AsyncClient() as client:
            # Step 1 — Login once, reuse TGT for this session
            username, tgt = await login(client)

            while True:
                # Step 2 — Pick service and action
                service = pick_service()
                method = pick_action()

                # Step 3 — One ST per (TGT + service) combination
                ticket, session_key = await request_ticket(client, tgt, service)

                if method == "GET":
                    # First call → list (authenticator #1)
                    authenticator = make_authenticator(username, session_key)
                    status, body = await call_list(client, service, ticket, authenticator, method)

                    if status == 200:
                        record_id = display_list(body)
                        if record_id:
                            # Second call → detail
                            authenticator = make_authenticator(username, session_key)
                            status, body = await call_record(
                                client, service, ticket, authenticator, method, record_id
                            )
                            display_result(status, body)
                    else:
                        display_result(status, body)

                else:
                    # POST / DELETE
                    authenticator = make_authenticator(username, session_key)
                    status, body = await call_list(client, service, ticket, authenticator, method)
                    display_result(status, body)

                # Ask what to do next
                print(f"{BOLD}{'─' * 48}{RESET}")
                print(f"  [1] Access another service (same user)")
                print(f"  [2] Log out and switch user")
                print(f"  [3] Exit")
                choice = input(f"\n{BOLD}Choice: {RESET}").strip()

                if choice == "1":
                    continue  # stay in inner loop, same user
                elif choice == "2":
                    print(f"\n{CYAN}Logging out '{username}'...{RESET}\n")
                    break  # breaks inner loop → outer loop re-runs login()
                else:
                    print(f"\n{CYAN}Session ended. Goodbye.{RESET}\n")
                    return  # exits everything

if __name__ == "__main__":
    asyncio.run(main())