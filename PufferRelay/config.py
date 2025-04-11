from PufferRelay.core_imports import os
from PufferRelay.core_imports import dotenv

# Load environment variables from a .env file (optional)
dotenv.load_dotenv()

# Get the project root directory
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Database Configuration
DB_TYPE = "sqlite"  # Could be "postgresql", "mysql", etc.
DB_NAME = os.getenv("DB_NAME", os.path.join(PROJECT_ROOT, "extracted_data.db"))  # Default is SQLite file

# PCAP File Storage
PCAP_STORAGE_FILE = os.getenv("PCAP_STORAGE_FILE", os.path.join(PROJECT_ROOT, "network_capture_ftp.pcapng"))
# PCAP_STORAGE_PATH = os.getenv("PCAP_STORAGE_PATH", os.path.join(PROJECT_ROOT, "pcap_files"))

# Logging Configuration
LOG_FILE = os.getenv("LOG_FILE", os.path.join(PROJECT_ROOT, "app.log"))
LOG_LEVEL = "INFO"

# Other Settings
DEBUG_MODE = os.getenv("DEBUG_MODE", "False").lower() == "true"