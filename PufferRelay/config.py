from PufferRelay.core_imports import os
from PufferRelay.core_imports import dotenv

# Load environment variables from a .env file (optional)
dotenv.load_dotenv()

# Database Configuration
DB_TYPE = "sqlite"  # Could be "postgresql", "mysql", etc.
DB_NAME = os.getenv("DB_NAME", "c://Users/33695/Documents/Projects/Python/GIT/PufferRelay/ldap_bind_requests.db")  # Default is SQLite file

# PCAP File Storage
PCAP_STORAGE_FILE = os.getenv("PCAP_STORAGE_FILE", "c://Users/33695/Documents/Projects/Python/GIT/PufferRelay/network_capture_ftp.pcapng")
# PCAP_STORAGE_PATH = os.getenv("PCAP_STORAGE_PATH", "/var/logs/pcap_files")

# Logging Configuration
LOG_FILE = os.getenv("LOG_FILE", "app.log")
LOG_LEVEL = "INFO"

# Other Settings
DEBUG_MODE = os.getenv("DEBUG_MODE", "False").lower() == "true"