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

# ============================================================================
# reputation_manager.py
# ============================================================================

"""
Reputation manager module for browsertriage.
Coordinates multiple reputation services (API-based and file-based).
"""

import hashlib
import time
import logging
from pathlib import Path

from reputation.api_reputation import ReputationResult, VirusTotalService
from reputation.local_reputation import URLhausService
from reputation.local_reputation import LocalMBLService

# Configure logging
logger = logging.getLogger(__name__)

class ReputationManager:
    """Manager class for coordinating multiple reputation services."""
    
    def __init__(self):
        self.api_services = {}      # API-based services (VirusTotal, etc.)
        self.file_services = {}     # File-based services (MBL, URLhaus, etc.)
        self.cache = {}             # Simple in-memory cache
        self.cache_duration = 3600  # Cache results for 1 hour
        
    def add_api_service(self, service, name=None):
        """Add an API-based reputation service to the manager."""
        service_name = name or service.service_name
        self.api_services[service_name] = service
        logger.info(f"Added API reputation service: {service_name}")
    
    def add_file_service(self, service, name=None):
        """Add a file-based reputation service to the manager."""
        service_name = name or service.service_name
        self.file_services[service_name] = service
        logger.info(f"Added file-based reputation service: {service_name}")
    
    def remove_service(self, name):
        """Remove a reputation service from the manager."""
        if name in self.api_services:
            del self.api_services[name]
            logger.info(f"Removed API reputation service: {name}")
        elif name in self.file_services:
            del self.file_services[name]
            logger.info(f"Removed file-based reputation service: {name}")

    def add_service(self, service, name=None):
        """Add a reputation service to the manager (automatically detects type)."""
        service_name = name or service.service_name
        # Check if it's an API service or file service based on class type
        if hasattr(service, 'api_key'):
            # It's an API service
            self.api_services[service_name] = service
            logger.info(f"Added API reputation service: {service_name}")
        else:
            # It's a file service
            self.file_services[service_name] = service
            logger.info(f"Added file-based reputation service: {service_name}")
    
    def check_url(self, url, services=None):
        """
        Check URL reputation using specified services.
        Args:
            url: URL to check
            services: List of service names to use. If None, use all available services.
        Returns:
            Dict mapping service names to ReputationResult objects
        """
        # Check cache first
        cache_key = self._get_cache_key(url)
        if cache_key in self.cache:
            cached_result, timestamp = self.cache[cache_key]
            if time.time() - timestamp < self.cache_duration:
                logger.debug(f"Using cached result for {url}")
                return cached_result
        # Determine which services to use
        all_services = {**self.api_services, **self.file_services}
        if services is None:
            services_to_use = list(all_services.keys())
        else:
            services_to_use = [s for s in services if s in all_services]
        results = {}
        # Check file-based services first (they're fast)
        for service_name in services_to_use:
            if service_name in self.file_services:
                service = self.file_services[service_name]
                logger.debug(f"Checking {url} with file-based service: {service_name}")
                if not service.is_configured():
                    logger.warning(f"File service {service_name} is not properly configured, skipping")
                    continue
                try:
                    result = service.check_url(url)
                    results[service_name] = result
                except Exception as e:
                    logger.error(f"Error checking {url} with {service_name}: {e}")
                    error_result = ReputationResult(url, service_name)
                    error_result.error_message = str(e)
                    results[service_name] = error_result
        # Then check API-based services (they may have rate limits)
        for service_name in services_to_use:
            if service_name in self.api_services:
                service = self.api_services[service_name]
                logger.debug(f"Checking {url} with API service: {service_name}")
                if not service.is_configured():
                    logger.warning(f"API service {service_name} is not properly configured, skipping")
                    continue
                try:
                    result = service.check_url(url)
                    results[service_name] = result
                    if result.rate_limited:
                        logger.warning(f"Rate limited by {service_name}")
                except Exception as e:
                    logger.error(f"Error checking {url} with {service_name}: {e}")
                    error_result = ReputationResult(url, service_name)
                    error_result.error_message = str(e)
                    results[service_name] = error_result
        # Cache the results
        self.cache[cache_key] = (results, time.time())
        return results
    
    def check_urls_batch_with_confirmation(self, urls, services=None):
        """
        Check multiple URLs using specified services, with VirusTotal rate limit confirmation.
        Args:
            urls: List of URLs to check
            services: List of service names to use
        Returns:
            Dict mapping URLs to service results
        """
        # Check if VirusTotal is in the services to use
        all_services = {**self.api_services, **self.file_services}
        if services is None:
            services_to_use = list(all_services.keys())
        else:
            services_to_use = [s for s in services if s in all_services]
        # Check if VirusTotal service is configured and will be used
        vt_will_be_used = ('VirusTotal' in services_to_use and 
                          'VirusTotal' in self.api_services and 
                          self.api_services['VirusTotal'].is_configured())
        if vt_will_be_used and len(urls) > 0:
            # Show rate limit warning and get user confirmation
            warning_message = VirusTotalService.get_rate_limit_warning(len(urls))
            print(warning_message)
            # Get user confirmation
            while True:
                response = input("Do you want to proceed with VirusTotal analysis? (y/n): ").strip().lower()
                if response in ['y', 'yes']:
                    print("Starting VirusTotal analysis...")
                    break
                elif response in ['n', 'no']:
                    print("Skipping VirusTotal analysis. Proceeding with other services only.")
                    # Remove VirusTotal from services to use
                    services_to_use = [s for s in services_to_use if s != 'VirusTotal']
                    break
                else:
                    print("Please enter 'y' for yes or 'n' for no.")
        # Proceed with URL checking
        all_results = {}
        for i, url in enumerate(urls, 1):
            if vt_will_be_used and 'VirusTotal' in services_to_use:
                print(f"Checking URL {i}/{len(urls)}: {url[:60]}{'...' if len(url) > 60 else ''}")
            else:
                logger.debug(f"Checking URL {i}/{len(urls)}: {url}")
            all_results[url] = self.check_url(url, services_to_use)
        return all_results
    
    def get_consensus_result(self, url, services=None):
        """
        Get a consensus result from multiple services.
        Args:
            url: URL to check
            services: List of service names to use
        Returns:
            Consensus ReputationResult
        """
        results = self.check_url(url, services)
        if not results:
            consensus = ReputationResult(url, "Consensus")
            consensus.error_message = "No services available"
            return consensus
        consensus = ReputationResult(url, "Consensus")
        # Count votes
        malicious_votes = 0
        suspicious_votes = 0
        clean_votes = 0
        total_confidence = 0.0
        valid_results = 0
        all_categories = set()
        all_threat_types = set()
        for service_name, result in results.items():
            if result.error_message:
                continue
            valid_results += 1
            total_confidence += result.confidence_score
            if result.is_malicious:
                malicious_votes += 1
            elif result.is_suspicious:
                suspicious_votes += 1
            elif result.is_clean:
                clean_votes += 1
            all_categories.update(result.categories)
            all_threat_types.update(result.threat_types)
        if valid_results == 0:
            consensus.error_message = "No valid results from any service"
            return consensus
        # Determine consensus
        if malicious_votes > 0:
            consensus.is_malicious = True
            consensus.is_clean = False
        elif suspicious_votes > 0:
            consensus.is_suspicious = True
            consensus.is_clean = False
        else:
            consensus.is_clean = True
        consensus.confidence_score = total_confidence / valid_results
        consensus.categories = list(all_categories)
        consensus.threat_types = list(all_threat_types)
        # Add voting information
        consensus.additional_info = {
            'malicious_votes': malicious_votes,
            'suspicious_votes': suspicious_votes,
            'clean_votes': clean_votes,
            'total_services': valid_results,
            'service_results': {name: result.to_dict() for name, result in results.items()}
        }
        return consensus
    
    def _get_cache_key(self, url):
        """Generate cache key for URL."""
        return hashlib.md5(url.encode()).hexdigest()
    
    def clear_cache(self):
        """Clear the results cache."""
        self.cache.clear()
        logger.info("Cleared reputation cache")
    
    def get_available_services(self):
        """Get list of available service names by type."""
        return {
            'api_services': list(self.api_services.keys()),
            'file_services': list(self.file_services.keys())
        }
    
    def get_configured_services(self):
        """Get list of all properly configured service names."""
        configured_api = [name for name, service in self.api_services.items() if service.is_configured()]
        configured_file = [name for name, service in self.file_services.items() if service.is_configured()]
        return configured_api + configured_file
    
    def print_service_status(self):
        """Print the status of all configured services."""
        print("\n" + "="*60)
        print("REPUTATION SERVICES STATUS")
        print("="*60)
        # API Services
        print("API-based Services:")
        if not self.api_services:
            print("  None configured")
        else:
            for name, service in self.api_services.items():
                status = "✓ Configured" if service.is_configured() else "✗ Not configured"
                print(f"  {name}: {status}")
        print()
        # File Services  
        print("File-based Services:")
        if not self.file_services:
            print("  None configured")
        else:
            for name, service in self.file_services.items():
                status = "✓ Configured" if service.is_configured() else "✗ Not configured"
                print(f"  {name}: {status}")
                # Show additional info for URLhaus
                if hasattr(service, 'get_feed_info'):
                    feed_info = service.get_feed_info()
                    print(f"    URLs loaded: {feed_info['urls_count']}")
                    print(f"    Domains loaded: {feed_info['domains_count']}")
        print("="*60)


# Convenience function for easy integration
def create_reputation_manager(vt_api_key=None, 
                            urlhaus_data_dir=None,
                            urlhaus_auto_download=False,
                            mbl_file_path=None):
    """
    Create a ReputationManager with common services configured.
    Args:
        vt_api_key: VirusTotal API key
        urlhaus_data_dir: Directory for URLhaus data files (will be created if not exists)
        urlhaus_auto_download: Whether to automatically download URLhaus feeds
        mbl_file_path: Path to local Master Block List file
    Returns:
        Configured ReputationManager
    """
    manager = ReputationManager()
    # Add VirusTotal if API key provided
    if vt_api_key:
        vt_service = VirusTotalService(vt_api_key)
        manager.add_api_service(vt_service, "VirusTotal")
    # Add URLhaus (local feeds)
    urlhaus_service = URLhausService(data_dir=urlhaus_data_dir, auto_download=urlhaus_auto_download)
    manager.add_file_service(urlhaus_service, "URLhaus")
    # Add local MBL if file path provided
    if mbl_file_path:
        mbl_service = LocalMBLService(mbl_file_path)
        manager.add_file_service(mbl_service, "LocalMBL")
    return manager
