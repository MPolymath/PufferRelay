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

from PufferRelay.core_imports import sqlite3
from PufferRelay.core_imports import os
from PufferRelay.core_imports import logging
from PufferRelay.core_imports import sys
from PufferRelay.config import DB_NAME

# Configure logging
logging.basicConfig(level=logging.INFO)

def get_db_connection():
    """
    Establish a connection to the SQLite database.

    Returns:
        sqlite3.Connection: A connection object to the SQLite database.
    """
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row  # Allows dictionary-like row access
        logging.info(f"Connected to SQLite database: {DB_NAME}")
        return conn
    except sqlite3.Error as e:
        logging.error(f"Database connection error: {e}")
        logging.error(f"Database path: {DB_NAME}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error while connecting to database: {e}")
        logging.error(f"Database path: {DB_NAME}")
        return None

def close_connection(conn):
    """
    Closes the database connection safely.

    Args:
        conn (sqlite3.Connection): The connection object to close.
    """
    if conn:
        try:
            conn.close()
            logging.info("Database connection closed.")
        except Exception as e:
            logging.error(f"Error while closing database connection: {e}")