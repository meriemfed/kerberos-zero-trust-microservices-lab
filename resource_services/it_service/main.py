# resource_services/it_service/main.py
import uvicorn
from shared.config import PORTS
from shared.pep_factory import create_pep_app
from resource_services.it_service.data import get_filtered_records

app = create_pep_app("resource-it", "it", "confidential", get_filtered_records)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=PORTS["IT_SERVICE"])
