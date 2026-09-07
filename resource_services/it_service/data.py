# it_service/data.py

IT_RECORDS = [
    {"id": 1, "asset": "Core Router Config", "status": "Active", "classification": "secret"},
    {"id": 2, "asset": "Helpdesk FAQ", "status": "Public", "classification": "public"},
    {"id": 3, "asset": "Server Rack 4 Map", "status": "Internal", "classification": "confidential"},
    {"id": 4, "asset": "Vulnerability Report", "status": "Critical", "classification": "secret"}
]

def get_filtered_records():

        return IT_RECORDS