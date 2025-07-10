# ============================================================================
# remote_manager.py
# ============================================================================

"""
Remote execution manager for browsertriage.
Handles platform detection and delegation to appropriate executors.
"""

import socket
import logging

from .windows_remote import WindowsRemoteExecutor
from .linux_remote import LinuxRemoteExecutor

# Configure logging
logger = logging.getLogger(__name__)

class RemoteManager:
    """Manages remote browser artifact extraction."""
    
    def __init__(self, verbose=False):
        """Initialize the remote manager."""
        self.verbose = verbose
        self.windows_executor = WindowsRemoteExecutor(method='auto')  # Try WinRM, fallback to WMI
        self.linux_executor = LinuxRemoteExecutor()
    
    def set_verbose(self, verbose):
        """Set verbose mode for all executors."""
        self.verbose = verbose

    def extract(self, hostname, username, password, target_user='all', browser='all'):
        """
        Extract browser artifacts from a remote system.
        Args:
            hostname: Remote host IP address or hostname
            username: Username for remote authentication
            password: Password for remote authentication
            target_user: Target user to extract browser data for (or 'all' for all users)
            browser: Browser to extract (or 'all' for all browsers)
        Returns:
            Dictionary containing extracted browser artifacts
        """
        # Detect OS type
        is_windows = self.detect_windows_system(hostname)
        logger.info(f"Detected remote system type: {'Windows' if is_windows else 'Linux'}")
        if is_windows:
            return self.windows_executor.extract(
                hostname, username, password, target_user, browser
            )
        else:
            return self.linux_executor.extract(
                hostname, username, password, target_user, browser
            )
    
    @staticmethod
    def detect_windows_system(hostname):
        """
        Detect if a remote system is Windows or Linux.
        Args:
            hostname: Remote hostname
        Returns:
            True if Windows, False if Linux/Unix
        """
        try:
            # Try to connect to port 445 (SMB) - typically open on Windows
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((hostname, 445))
            s.close()
            if result == 0:
                # Port is open, likely Windows
                logger.debug(f"Host {hostname} has open port 445 (SMB), likely Windows")
                return True
            # Try to connect to port 22 (SSH) - typically open on Linux
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((hostname, 22))
            s.close()
            if result == 0:
                # Port is open, likely Linux
                logger.debug(f"Host {hostname} has open port 22 (SSH), likely Linux")
                return False
            # If neither port is open, default to Windows
            logger.warning(f"Could not determine OS type for {hostname}, defaulting to Windows")
            return True
        except Exception as e:
            # On error, default to Windows
            logger.error(f"Error detecting system type: {e}")
            return True