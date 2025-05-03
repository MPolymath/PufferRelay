import logging
import sys
from logging.handlers import RotatingFileHandler
import os

class PysharkFilter(logging.Filter):
    def filter(self, record):
        # Filter out pyshark cleanup messages
        if 'Cleanup Subprocess' in record.getMessage():
            return False
        return True

def setup_logger():
    """Setup logging configuration"""
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # Suppress pyshark debug messages
    logging.getLogger('pyshark').setLevel(logging.WARNING)
    logging.getLogger('FileCapture').setLevel(logging.WARNING)
    
    # Add filter to suppress cleanup messages
    cleanup_filter = PysharkFilter()
    logging.getLogger('pyshark').addFilter(cleanup_filter)
    logging.getLogger('FileCapture').addFilter(cleanup_filter)

    # Create formatters
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_formatter = logging.Formatter(
        '%(levelname)s: %(message)s'
    )

    # File handler with rotation
    file_handler = RotatingFileHandler(
        'logs/pufferrelay.log',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.DEBUG)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(logging.INFO)

    # Add handlers to root logger
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    return root_logger
