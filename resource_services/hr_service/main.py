# resource_services/hr_service/main.py
import uvicorn
from shared.config import PORTS
from shared.pep_factory import create_pep_app
from resource_services.hr_service.data import get_filtered_records

app = create_pep_app("resource-hr", "hr", "confidential", get_filtered_records)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=PORTS["HR_SERVICE"])
