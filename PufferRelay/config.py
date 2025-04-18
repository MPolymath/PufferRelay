# Created by Massamba DIOUF
#
# This file is part of PufferRelay.
#
# PufferRelay is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# PufferRelay is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with PufferRelay. If not, see <http://www.gnu.org/licenses/>.
#
# Credits: Portions of this code were adapted from PCredz (https://github.com/lgandx/PCredz)
#         (c) Laurent Gaffie GNU General Public License v3.0.

from PufferRelay.core_imports import os
from PufferRelay.core_imports import dotenv
from PufferRelay.core_imports import Path

# Get the current working directory
CURRENT_DIR = Path.cwd()

# Database configuration - will be created in the current directory
DB_NAME = str(CURRENT_DIR / "extracted_data.db")

# Logging configuration
LOG_LEVEL = "INFO"

# PCAP storage configuration
PCAP_STORAGE_FILE = str(CURRENT_DIR / "pcap_storage.txt")

# Load environment variables from a .env file (optional)
dotenv.load_dotenv()

# Get the project root directory
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Database Configuration
DB_TYPE = "sqlite"  # Could be "postgresql", "mysql", etc.
# PCAP_STORAGE_PATH = os.getenv("PCAP_STORAGE_PATH", os.path.join(PROJECT_ROOT, "pcap_files"))

# Logging Configuration
LOG_FILE = os.getenv("LOG_FILE", os.path.join(PROJECT_ROOT, "app.log"))

# Other Settings
DEBUG_MODE = os.getenv("DEBUG_MODE", "False").lower() == "true"