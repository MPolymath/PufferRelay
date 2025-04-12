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

def ensure_db_directory():
    """
    Ensures the directory for the database file exists.
    """
    db_dir = os.path.dirname(DB_NAME)
    if not db_dir:  # If no directory specified, use current directory
        db_dir = os.getcwd()
    
    try:
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)
            logging.info(f"Created database directory: {db_dir}")
        
        # Check if directory is writable
        test_file = os.path.join(db_dir, '.test_write')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        
    except OSError as e:
        logging.error(f"Failed to create or access database directory: {e}")
        logging.error(f"Directory path: {db_dir}")
        logging.error(f"Current working directory: {os.getcwd()}")
        raise

def get_db_connection():
    """
    Establish a connection to the SQLite database.

    Returns:
        sqlite3.Connection: A connection object to the SQLite database.
    """
    try:
        ensure_db_directory()
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row  # Allows dictionary-like row access
        logging.info(f"Connected to SQLite database: {DB_NAME}")
        return conn
    except sqlite3.Error as e:
        logging.error(f"Database connection error: {e}")
        logging.error(f"Database path: {DB_NAME}")
        return None
    except OSError as e:
        logging.error(f"Database directory error: {e}")
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