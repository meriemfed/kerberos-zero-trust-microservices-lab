# kdc_service/add_user.py
import json
import os
import getpass
from kdc_service.user_directory import derive_kerberos_key

# ---  Define Allowed Values ---
VALID_ROLES = ["admin", "manager", "employee"]
VALID_DEPARTMENTS = ["finance", "hr", "it", "ops"]
VALID_CLEARANCES = ["public", "confidential", "secret"]
VALID_LOCATIONS = ["internal", "external"]

def get_validated_input(prompt, valid_options):
    while True:
        val = input(f"{prompt} ({', '.join(valid_options)}): ").strip().lower()
        if val in valid_options:
            return val
        print(f"  [!] Invalid choice. Please choose from: {', '.join(valid_options)}")

def provision_user():
    print("\n=== SecureCorp Identity Adding Tool ===")
    username = input("Username: ").strip().lower()
    password = getpass.getpass("Password: ").strip()
    
    # Use the validation helper for project-specific attributes
    role = get_validated_input("Role", VALID_ROLES)
    department = get_validated_input("Department", VALID_DEPARTMENTS)
    clearance = get_validated_input("Clearance Level", VALID_CLEARANCES)

    # Functional roles are free-text but we clean the list
    func_roles_input = input("Functional Roles (comma-separated): ").strip()
    functional_roles = [r.strip().lower() for r in func_roles_input.split(",")] if func_roles_input else []

    print(f"\n[+] Deriving Kerberos key for {username}...")
    derived_key = derive_kerberos_key(username, password)

    new_user_data = {
        "derived_key": derived_key,
        "role": role,
        "department": department,
        "clearance": clearance,
        "functional_roles": functional_roles
    }

    base_path = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(base_path, "kdc_service", "users.json")
    
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            users = json.load(f)
    else:
        users = {}

    users[username] = new_user_data
    
    with open(file_path, "w") as f:
        json.dump(users, f, indent=4)

    print(f"SUCCESS: User '{username}' securely added to users.json!")

if __name__ == "__main__":
    provision_user()