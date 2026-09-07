# ops_service/data.py

OPS_RECORDS = [
    {"id": 301, "task": "Supply Chain Strategy", "priority": "High", "classification": "secret"},
    {"id": 302, "task": "Daily Shift Schedule", "priority": "Normal", "classification": "public"},
    {"id": 303, "task": "Warehouse Inventory", "priority": "Medium", "classification": "confidential"},
    {"id": 304, "task": "Vendor Contracts", "priority": "High", "classification": "confidential"}
]

def get_filtered_records():

        return OPS_RECORDS