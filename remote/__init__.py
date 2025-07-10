# __init__.py
"""
Remote execution package for browsertriage.
Enables browser artifact extraction from remote systems without Python dependency.
"""

from .remote_manager import RemoteManager
from .windows_remote import WindowsRemoteExecutor
from .linux_remote import LinuxRemoteExecutor

__all__ = ['RemoteManager', 'WindowsRemoteExecutor', 'LinuxRemoteExecutor']