import logging
import json
from modules.database import init_db

def setup_logging():
    init_db()
    ip_logger = logging.getLogger("IPLogger")
    ip_logger.setLevel(logging.INFO)
    ip_handler = logging.FileHandler("ids_all_ips.log", mode="a")
    ip_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s", "%Y-%m-%d %H:%M:%S"))
    ip_logger.addHandler(ip_handler)

    logging.info("IDS started. Monitoring network traffic for suspicious activity.")

import json

def log_packet_data(data):
    ip_logger = logging.getLogger("IPLogger")
    try:
        ip_logger.info(json.dumps(data, ensure_ascii=False))
    except (TypeError, ValueError) as e:
        logging.error(f"Failed to serialize packet data: {str(e)}")
        ip_logger.info(str(data))
