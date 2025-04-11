from PufferRelay.core_imports import (
    sqlite3,
    os,
    logging,
    time
)
from PufferRelay.config import DB_NAME

# Current schema version - increment this when making schema changes
CURRENT_SCHEMA_VERSION = 1

def get_db_schema_version(conn):
    """
    Get the current schema version from the database.
    
    Args:
        conn (sqlite3.Connection): Database connection
        
    Returns:
        int: Schema version or 0 if not found
    """
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA user_version")
        return cursor.fetchone()[0]
    except sqlite3.Error as e:
        logging.error(f"Error getting schema version: {e}")
        return 0

def check_database_version():
    """
    Check if the database exists and has the correct schema version.
    Returns True if the database can be used, False if it should be recreated.
    
    Returns:
        bool: True if database is ready to use, False if program should exit
    """
    if not os.path.exists(DB_NAME):
        return True  # No existing database, can create new one
    
    try:
        conn = sqlite3.connect(DB_NAME)
        current_version = get_db_schema_version(conn)
        
        if current_version == CURRENT_SCHEMA_VERSION:
            logging.info("Database schema version matches current version")
            return True
            
        logging.warning(f"Database schema version mismatch. Current: {current_version}, Required: {CURRENT_SCHEMA_VERSION}")
        
        # Ask user what to do
        while True:
            response = input("Database schema version mismatch. Would you like to:\n"
                           "1. Delete the old database and create a new one\n"
                           "2. Move the old database to a backup file\n"
                           "3. Exit the program\n"
                           "Enter your choice (1-3): ")
            
            if response == "1":
                conn.close()
                os.remove(DB_NAME)
                logging.info("Old database deleted")
                return True
            elif response == "2":
                backup_name = f"{DB_NAME}.v{current_version}.bak"
                conn.close()
                os.rename(DB_NAME, backup_name)
                logging.info(f"Old database moved to {backup_name}")
                return True
            elif response == "3":
                logging.info("Exiting program as requested")
                return False
            else:
                print("Invalid choice. Please enter 1, 2, or 3.")
                
    except sqlite3.Error as e:
        logging.error(f"Error checking database version: {e}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

def set_db_schema_version(conn):
    """
    Set the schema version in the database.
    
    Args:
        conn (sqlite3.Connection): Database connection
    """
    try:
        cursor = conn.cursor()
        cursor.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Error setting schema version: {e}") 