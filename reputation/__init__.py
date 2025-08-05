#!/usr/bin/env python3
# ============================================================================
# browsertriage.py (or appropriate filename)
# BrowserTriage - Browser Artifact Extraction and Threat Detection Tool
# 
# Copyright (C) 2024 Will Heisler
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# ============================================================================

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
