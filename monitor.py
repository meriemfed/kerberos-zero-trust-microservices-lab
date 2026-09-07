# monitor.py
import time
import json
import os

# Colors for the terminal
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

LOG_FILE = "audit_bus.log"

def format_log(line):
    try:
        data = json.loads(line)
        
        # Mapping to your event_logger.py structure:
        service    = data.get("service", "UNKNOWN")
        event      = data.get("event_type", "EVENT")  # Changed from 'event'
        details    = data.get("details", {})          # Changed from 'data'
        severity   = data.get("status", "INFO")       # Changed from 'severity'
        
        # Pick color based on your 'status' values
        color = RESET
        if severity in ["DENIED", "DENY", "ALERT", "401", "403", "BLOCKED", "FAILURE"]: 
            color = RED
        elif severity in ["WARNING", "ALERT"]: 
            color = YELLOW
        elif severity in ["SUCCESS", "PERMIT", "Authorized"]: 
            color = GREEN

        # Clean up the timestamp for the display
        timestamp = data.get("timestamp", "").split("T")[-1].replace("Z", "") 

        return f"{CYAN}[{timestamp}]{RESET} {BOLD}{service:<16}{RESET} | {color}{event:<20}{RESET} | {details}"
    except Exception as e:
        return f"{RED}Error parsing log line: {e}{RESET}"

def tail_f():
    print(f"\n{BOLD}{CYAN}🚀 SecureCorp Live SIEM Monitor Starting...{RESET}")
    print(f"{CYAN}{'─' * 80}{RESET}")
    
    # Create file if it doesn't exist
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f: f.write("")

    with open(LOG_FILE, "r") as f:
        # Go to the end of the file
        f.seek(0, os.SEEK_END)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1) # Wait for new logs
                continue
            
            print(format_log(line))

if __name__ == "__main__":
    try:
        tail_f()
    except KeyboardInterrupt:
        print(f"\n{RED}Stopping logs Monitor...{RESET}")