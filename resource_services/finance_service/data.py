# finance_service/data.py

FINANCE_RECORDS = [
    {"id": 1, "item": "Payroll Q1", "amount": "$500k", "classification": "secret"},
    {"id": 2, "item": "Supplies", "amount": "$1k", "classification": "public"},
    {"id": 3, "item": "Audit Report", "amount": "N/A", "classification": "confidential"}
]

def get_filtered_records():

        return FINANCE_RECORDS