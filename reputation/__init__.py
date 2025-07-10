# __init__.py
"""
Reputation services package for browsertriage.
Provides URL reputation checking via multiple services (API-based and file-based).
"""

from .api_reputation import (
    ReputationResult,
    VirusTotalService
)

from .local_reputation import (
    LocalMBLService,
    URLhausService
)

from .reputation_manager import (
    ReputationManager,
    create_reputation_manager
)

__all__ = [
    'ReputationResult',
    'VirusTotalService',
    'LocalMBLService', 
    'URLhausService',
    'ReputationManager',
    'create_reputation_manager'
]