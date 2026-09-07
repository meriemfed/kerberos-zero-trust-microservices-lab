# kdc_service/user_directory.py
import json
import os
import hashlib
import binascii


# inspired by kerberos,it derives a client key from the user password
def derive_kerberos_key(username: str, plaintext_password: str) -> str:
    """Simulates Kerberos V5 String-to-Key (S2K) using PBKDF2."""
    # Creates a "salt" using the user's name.
    salt = username.encode('utf-8')
    # Executes the PBKDF2 (Password-Based Key Derivation Function 2) algorithm using SHA-256.
    derived = hashlib.pbkdf2_hmac('sha256', plaintext_password.encode('utf-8'), salt, 100000)
    return binascii.hexlify(derived).decode('utf-8')

#Verifies a login attempt 
def authenticate_user(username: str, plaintext_password: str):
    base_path = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(base_path, "users.json")
    
    # If the database doesn't exist yet, fail securely
    if not os.path.exists(file_path):
        return None
        
    with open(file_path, "r") as f:
        users = json.load(f)
        
    user = users.get(username)
    if not user:
        return None
        
    # Derive the key from the login attempt
    attempted_key = derive_kerberos_key(username, plaintext_password)
    
    # Compare against the database
    if attempted_key == user.get("derived_key"):
        # Strip the sensitive key data before returning the ABAC/RBAC attributes
        return {k: v for k, v in user.items() if k != "derived_key"}
        
    return None