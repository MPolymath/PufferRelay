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

from PufferRelay.core_imports import (
    sqlite3,
    os,
    logging,
    time
)
from PufferRelay.config import DB_NAME

# Current schema version - increment this when making schema changes
CURRENT_SCHEMA_VERSION = 3

def migrate_database(conn):
    """Bring an existing database up to CURRENT_SCHEMA_VERSION.

    PRAGMA user_version is the source of truth; the legacy ``schema_version``
    table (if present) is kept in sync for older releases.

    v3 repairs ``netbios_requests``: older databases used columns that the
    insert path never matched, so NetBIOS findings were silently lost. The
    table is rebuilt (there is no useful data to preserve) and
    ``observed_services`` is added by create_database().

    Returns False when the database is newer than this tool.
    """
    try:
        cursor = conn.cursor()
        legacy = 0
        try:
            cursor.execute("SELECT version FROM schema_version")
            row = cursor.fetchone()
            if row and str(row[0]).strip().isdigit():
                legacy = int(str(row[0]).strip())
        except sqlite3.Error:
            legacy = 0

        cursor.execute("PRAGMA user_version")
        version = int(cursor.fetchone()[0] or 0)
        version = max(version, legacy)

        if version > CURRENT_SCHEMA_VERSION:
            logging.error(
                "Database schema v%s is newer than this PufferRelay (supports v%s). "
                "Upgrade PufferRelay or use a fresh database.",
                version,
                CURRENT_SCHEMA_VERSION,
            )
            return False

        if version < 3:
            cursor.execute("DROP TABLE IF EXISTS netbios_requests")

        cursor.execute("PRAGMA user_version = %d" % CURRENT_SCHEMA_VERSION)
        try:
            cursor.execute("CREATE TABLE IF NOT EXISTS schema_version (version TEXT)")
            cursor.execute("DELETE FROM schema_version")
            cursor.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                (str(CURRENT_SCHEMA_VERSION),),
            )
        except sqlite3.Error:
            pass
        conn.commit()
        return True
    except sqlite3.Error as e:
        logging.error("Database migration error: %s", e)
        return False


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
    """Check if the database schema version matches the current version."""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Check if version table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'")
        if not cursor.fetchone():
            # Create version table if it doesn't exist
            cursor.execute("CREATE TABLE schema_version (version TEXT)")
            cursor.execute("INSERT INTO schema_version (version) VALUES (?)", (CURRENT_SCHEMA_VERSION,))
            conn.commit()
            return True
        
        # Get current version
        cursor.execute("SELECT version FROM schema_version")
        current_version = cursor.fetchone()[0]
        
        # Return True if versions match, False if they don't
        return str(current_version) == str(CURRENT_SCHEMA_VERSION)
            
    except sqlite3.Error as e:
        logging.error(f"Database version check error: {str(e)}")
        return False
    finally:
        if conn:
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