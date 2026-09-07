# run_all.py
import subprocess
import sys
import time
import os

SERVICES = [
    {"name": "KDC",          "module": "kdc_service.main",                        "port": 3001},
    {"name": "PDP",          "module": "pdp_service.main",                        "port": 3006},
    {"name": "HR",           "module": "resource_services.hr_service.main",       "port": 3011},
    {"name": "Finance",      "module": "resource_services.finance_service.main",  "port": 3012},
    {"name": "IT",           "module": "resource_services.it_service.main",       "port": 3013},
    {"name": "OPS",          "module": "resource_services.ops_service.main",      "port": 3014},
    {"name": "Gateway",      "module": "api_gateway.main",                        "port": 3000},
]

def start_services():
    processes = []
    print("\n╔══════════════════════════════════════╗")
    print("║       SecureCorp — Booting Up        ║")
    print("╚══════════════════════════════════════╝\n")

    for svc in SERVICES:
        cmd = [
            sys.executable, "-m", "uvicorn",
            svc["module"] + ":app",
            "--host", "0.0.0.0",
            "--port", str(svc["port"]),
        ]
        proc = subprocess.Popen(cmd)
        processes.append(proc)
        print(f"  ✓ {svc['name']:<12} started on port {svc['port']}")
        time.sleep(0.5)  # stagger startup

    print("\n  All services running. Gateway at http://localhost:3000")
    print("  Press Ctrl+C to shut down all services.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  Shutting down all services...")
        for proc in processes:
            proc.terminate()
        print("  Done.\n")

if __name__ == "__main__":
    start_services()