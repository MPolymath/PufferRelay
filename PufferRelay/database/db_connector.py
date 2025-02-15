from PufferRelay.core_imports import sqlite3
from PufferRelay.core_imports import os
from PufferRelay.core_imports import logging
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
        return None

def close_connection(conn):
    """
    Closes the database connection safely.

    Args:
        conn (sqlite3.Connection): The connection object to close.
    """
    if conn:
        conn.close()
        logging.info("Database connection closed.")