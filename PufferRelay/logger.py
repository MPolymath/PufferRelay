import logging
import sys
from logging.handlers import RotatingFileHandler
import os
from PufferRelay.config import LOG_LEVEL

class PysharkFilter(logging.Filter):
    def filter(self, record):
        # Filter out pyshark cleanup messages
        if 'Cleanup Subprocess' in record.getMessage():
            return False
        return True

def setup_logger(log_level=None):
    """
    Set up the logging configuration.
    
    Args:
        log_level (int, optional): The logging level to use. If None, uses the default from config.
    """
    # Use provided log level or default from config
    level = log_level if log_level is not None else getattr(logging, LOG_LEVEL)
    
    # Configure logging
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Configure pyshark logging
    pyshark_logger = logging.getLogger('FileCapture')
    pyshark_logger.setLevel(level)
    
    logging.info("Starting PufferRelay...")

    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

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
