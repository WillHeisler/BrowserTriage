# ============================================================================
# local_reputation.py
# ============================================================================

"""
File-based URL reputation services module for browsertriage.
Supports local MBL CSV files and downloaded URLhaus feeds.
"""

import os
import csv
import time
import logging
import requests
from pathlib import Path
from datetime import datetime, timedelta
from urllib.parse import urlparse

from .api_reputation import ReputationResult

# Configure logging
logger = logging.getLogger(__name__)

class FileServiceBase:
    """Base class for file-based URL reputation services."""
    
    def __init__(self):
        self.service_name = self.__class__.__name__.replace('Service', '')
        self.rate_limit_delay = 0.0  # No rate limiting for local checks
        
    def check_url(self, url):
        """
        Check the reputation of a single URL.
        Args:
            url: URL to check
        Returns:
            ReputationResult: Standardized result object
        """
        raise NotImplementedError("Subclasses must implement check_url")
    
    def is_configured(self):
        """Check if the service is properly configured."""
        raise NotImplementedError("Subclasses must implement is_configured")

class LocalMBLService(FileServiceBase):
    """Local Master Block List (MBL) service implementation."""
    
    def __init__(self, mbl_file_path):
        super().__init__()
        self.mbl_file_path = Path(mbl_file_path)
        self.blocked_urls = set()
        self.blocked_domains = set()
        # Load the MBL file
        self._load_mbl_file()
    
    def _load_mbl_file(self):
        """Load the Master Block List from file."""
        try:
            if not self.mbl_file_path.exists():
                logger.error(f"MBL file not found: {self.mbl_file_path}")
                return
            logger.info(f"Loading MBL file: {self.mbl_file_path}")
            with open(self.mbl_file_path, 'r', encoding='utf-8') as f:
                if self.mbl_file_path.suffix.lower() == '.csv':
                    # CSV format - read first column
                    reader = csv.reader(f)
                    for row_num, row in enumerate(reader, 1):
                        if row and row[0] and not row[0].startswith('#'):  # Skip comments and empty rows
                            entry = row[0].strip().lower()
                            if entry:
                                self._add_entry(entry)
                else:
                    # Plain text format (one entry per line)
                    for line_num, line in enumerate(f, 1):
                        entry = line.strip().lower()
                        if entry and not entry.startswith('#'):  # Skip comments and empty lines
                            self._add_entry(entry)
            logger.info(f"Loaded {len(self.blocked_urls)} URLs and {len(self.blocked_domains)} domains from MBL")
        except Exception as e:
            logger.error(f"Error loading MBL file: {e}")
    
    def _add_entry(self, entry):
        """Add an entry to the appropriate set (URL or domain)."""
        try:
            # Check if it's a URL (contains protocol or path)
            if entry.startswith('http') or '/' in entry:
                self.blocked_urls.add(entry)
            else:
                # Treat as domain
                # Remove any port numbers
                if ':' in entry and not entry.startswith('['):  # Not IPv6
                    entry = entry.split(':')[0]
                self.blocked_domains.add(entry)
        except Exception as e:
            logger.debug(f"Error processing entry '{entry}': {e}")
    
    def check_url(self, url):
        """Check URL against local Master Block List."""
        result = ReputationResult(url, "LocalMBL")
        try:
            url_lower = url.lower()
            # Check exact URL match
            if url_lower in self.blocked_urls:
                result.is_malicious = True
                result.is_clean = False
                result.confidence_score = 1.0
                result.categories = ['blocked']
                result.threat_types = ['blocked']
                result.additional_info = {
                    'match_type': 'exact_url',
                    'source': 'local_mbl'
                }
                return result
            # Extract domain from URL for domain checking
            try:
                parsed = urlparse(url_lower)
                domain = parsed.netloc.lower()
                # Remove port if present
                if ':' in domain and not domain.startswith('['):  # Not IPv6
                    domain = domain.split(':')[0]
                # Check exact domain match
                if domain in self.blocked_domains:
                    result.is_malicious = True
                    result.is_clean = False
                    result.confidence_score = 1.0
                    result.categories = ['blocked']
                    result.threat_types = ['blocked']
                    result.additional_info = {
                        'match_type': 'domain',
                        'domain': domain,
                        'source': 'local_mbl'
                    }
                    return result
                # Check subdomain matches (e.g., sub.example.com matches example.com)
                domain_parts = domain.split('.')
                for i in range(len(domain_parts)):
                    parent_domain = '.'.join(domain_parts[i:])
                    if parent_domain in self.blocked_domains:
                        result.is_malicious = True
                        result.is_clean = False
                        result.confidence_score = 0.9  # Slightly lower confidence for subdomain match
                        result.categories = ['blocked']
                        result.threat_types = ['blocked']
                        result.additional_info = {
                            'match_type': 'parent_domain',
                            'matched_domain': parent_domain,
                            'actual_domain': domain,
                            'source': 'local_mbl'
                        }
                        return result
            except Exception as e:
                logger.debug(f"Error parsing URL {url}: {e}")
            # No match found
            result.is_clean = True
            result.confidence_score = 0.5  # Neutral confidence for local list
        except Exception as e:
            result.error_message = f"LocalMBL check failed: {str(e)}"
        return result
    
    def is_configured(self):
        """Check if MBL file is properly loaded."""
        return len(self.blocked_urls) > 0 or len(self.blocked_domains) > 0
    
    def get_mbl_info(self):
        """Get information about the loaded MBL."""
        info = {
            'file_path': str(self.mbl_file_path),
            'urls_count': len(self.blocked_urls),
            'domains_count': len(self.blocked_domains),
            'total_entries': len(self.blocked_urls) + len(self.blocked_domains)
        }
        if self.mbl_file_path.exists():
            stat = self.mbl_file_path.stat()
            info.update({
                'file_size_bytes': stat.st_size,
                'last_modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'file_exists': True
            })
        else:
            info['file_exists'] = False
        return info
    
    def print_sample_entries(self, max_entries=10):
        """Print some sample entries for debugging."""
        print(f"\nSample blocked domains (showing up to {max_entries}):")
        for i, domain in enumerate(list(self.blocked_domains)[:max_entries]):
            print(f"  {i+1}. {domain}")
        if self.blocked_urls:
            print(f"\nSample blocked URLs (showing up to {max_entries}):")
            for i, url in enumerate(list(self.blocked_urls)[:max_entries]):
                print(f"  {i+1}. {url}")

class URLhausService(FileServiceBase):
    """URLhaus service using downloaded local files (text format)."""
    
    def __init__(self, data_dir=None, auto_download=False):
        """
        Initialize URLhaus service with local data files.
        Args:
            data_dir: Directory containing URLhaus data files (default: ./urlhaus_data)
            auto_download: Whether to automatically download feeds if missing (default: False for security)
        """
        super().__init__()
        # Set up data directory
        if data_dir:
            self.data_dir = Path(data_dir)
        else:
            self.data_dir = Path.cwd() / "urlhaus_data"
        self.data_dir.mkdir(exist_ok=True)
        # URLhaus feed configuration - using text format
        self.feeds = {
            'urls': {
                'url': 'https://urlhaus.abuse.ch/downloads/text/',
                'file': self.data_dir / 'urlhaus_urls.txt',
                'max_age_hours': 24,  # Consider outdated after 24 hours
                'description': 'Recent malicious URLs (text format)'
            }
        }
        self.auto_download = auto_download
        logger.info(f"URLhaus auto_download: {auto_download}")
        self.malicious_urls = set()
        self.malicious_domains = set()
        # Load existing data
        logger.info("Loading URLhaus feeds...")
        self._load_feeds()
        logger.info(f"URLhaus service initialized: {len(self.malicious_urls)} URLs, {len(self.malicious_domains)} domains loaded")
    
    def _needs_update(self, file_path, max_age_hours):
        """Check if a feed file needs updating based on age."""
        if not file_path.exists():
            return True
        file_age = datetime.now() - datetime.fromtimestamp(file_path.stat().st_mtime)
        return file_age > timedelta(hours=max_age_hours)
    
    def download_feed(self, feed_name):
        """
        Manually download a specific URLhaus feed.
        Args:
            feed_name: Name of the feed to download ('urls')
        Returns:
            True if download was successful, False otherwise
        """
        if feed_name not in self.feeds:
            logger.error(f"Unknown feed: {feed_name}. Available feeds: {list(self.feeds.keys())}")
            return False
        feed_config = self.feeds[feed_name]
        try:
            logger.info(f"Downloading URLhaus {feed_name} feed...")
            logger.info(f"Description: {feed_config['description']}")
            logger.info(f"URL: {feed_config['url']}")
            headers = {
                'User-Agent': 'browsertriage_tool/1.0 (Incident Response Tool)'
            }
            response = requests.get(feed_config['url'], headers=headers, timeout=60)
            response.raise_for_status()
            # Write to file
            with open(feed_config['file'], 'wb') as f:
                f.write(response.content)
            logger.info(f"Successfully downloaded URLhaus {feed_name} feed ({len(response.content)} bytes)")
            logger.info(f"Saved to: {feed_config['file']}")
            # Reload data after download
            if self._load_feed(feed_name):
                logger.info(f"Feed {feed_name} loaded successfully")
                return True
            else:
                logger.error(f"Failed to load downloaded feed {feed_name}")
                return False
        except Exception as e:
            logger.error(f"Failed to download URLhaus {feed_name} feed: {e}")
            return False
    
    def _load_feeds(self):
        """Load URLhaus feeds from local files."""
        feeds_loaded = False
        for feed_name in self.feeds.keys():
            feed_config = self.feeds[feed_name]
            file_path = feed_config['file']
            # Check if file exists
            if not file_path.exists():
                logger.warning(f"URLhaus {feed_name} feed not found at {file_path}")
                if self.auto_download:
                    logger.info(f"Auto-downloading {feed_name} feed...")
                    if self.download_feed(feed_name):
                        feeds_loaded = True
                continue
            # Check if file is outdated
            if self._needs_update(file_path, feed_config['max_age_hours']):
                logger.warning(f"URLhaus {feed_name} feed is outdated (older than {feed_config['max_age_hours']} hours)")
                if self.auto_download:
                    logger.info(f"Auto-updating {feed_name} feed...")
                    if self.download_feed(feed_name):
                        feeds_loaded = True
                    continue
                else:
                    logger.warning(f"Using outdated {feed_name} feed. Consider downloading manually.")
            # Load the feed
            if self._load_feed(feed_name):
                feeds_loaded = True
        if feeds_loaded:
            logger.info(f"URLhaus feeds loaded: {len(self.malicious_urls)} URLs, {len(self.malicious_domains)} domains")
        else:
            logger.warning("No URLhaus feeds could be loaded")
    
    def _load_feed(self, feed_name):
        """Load a specific URLhaus feed from text file."""
        feed_config = self.feeds[feed_name]
        file_path = feed_config['file']
        try:
            logger.debug(f"Loading URLhaus {feed_name} feed from {file_path}")
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                urls_loaded = 0
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    # Each line should be a URL
                    url = line.lower()
                    if url.startswith('http'):
                        # Add full URL
                        self.malicious_urls.add(url)
                        # Extract and add domain
                        try:
                            parsed = urlparse(url)
                            domain = parsed.netloc.lower()
                            if domain:
                                self.malicious_domains.add(domain)
                        except:
                            pass
                        urls_loaded += 1
                logger.debug(f"Loaded {urls_loaded} URLs from URLhaus {feed_name} feed")
                return urls_loaded > 0
        except Exception as e:
            logger.error(f"Error loading URLhaus {feed_name} feed: {e}")
            return False
    
    def check_url(self, url):
        """Check URL against local URLhaus data."""
        result = ReputationResult(url, "URLhaus")
        try:
            url_lower = url.lower()
            # Check exact URL match
            if url_lower in self.malicious_urls:
                result.is_malicious = True
                result.is_clean = False
                result.confidence_score = 0.95  # High confidence for exact match
                result.categories = ['malware']
                result.threat_types = ['malware']
                result.additional_info = {
                    'match_type': 'exact_url',
                    'source': 'urlhaus_text_feed'
                }
                return result
            # Check domain match
            try:
                parsed = urlparse(url_lower)
                domain = parsed.netloc.lower()
                if domain in self.malicious_domains:
                    result.is_malicious = True
                    result.is_clean = False
                    result.confidence_score = 0.85  # Slightly lower for domain match
                    result.categories = ['malware']
                    result.threat_types = ['malware']
                    result.additional_info = {
                        'match_type': 'domain',
                        'domain': domain,
                        'source': 'urlhaus_text_feed'
                    }
                    return result
            except Exception as e:
                logger.debug(f"Error parsing URL {url}: {e}")
            # No match found
            result.is_clean = True
            result.confidence_score = 0.7  # Good confidence for clean result from URLhaus
        except Exception as e:
            result.error_message = f"URLhaus check failed: {str(e)}"
        return result
    
    def is_configured(self):
        """Check if URLhaus data is properly loaded."""
        return len(self.malicious_urls) > 0 or len(self.malicious_domains) > 0
    
    def get_feed_info(self):
        """Get information about loaded feeds."""
        info = {
            'urls_count': len(self.malicious_urls),
            'domains_count': len(self.malicious_domains),
            'feeds': {}
        }
        for feed_name, feed_config in self.feeds.items():
            file_path = feed_config['file']
            if file_path.exists():
                stat = file_path.stat()
                info['feeds'][feed_name] = {
                    'file_path': str(file_path),
                    'size_bytes': stat.st_size,
                    'last_modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'age_hours': (datetime.now() - datetime.fromtimestamp(stat.st_mtime)).total_seconds() / 3600,
                    'description': feed_config['description']
                }
            else:
                info['feeds'][feed_name] = {
                    'file_path': str(file_path),
                    'status': 'not_found',
                    'description': feed_config['description']
                }
        return info
    
    def print_manual_download_instructions(self):
        """Print instructions for manually downloading URLhaus feeds."""
        print("\n" + "="*80)
        print("URLHAUS MANUAL DOWNLOAD INSTRUCTIONS")
        print("="*80)
        print("If automatic downloads are disabled or fail, you can manually download")
        print("URLhaus feeds using the following URLs:")
        print()
        for feed_name, feed_config in self.feeds.items():
            print(f"Feed: {feed_name}")
            print(f"Description: {feed_config['description']}")
            print(f"Download URL: {feed_config['url']}")
            print(f"Save to: {feed_config['file']}")
            print(f"Recommended update frequency: Every {feed_config['max_age_hours']} hours")
            print("-" * 40)
        print("\nManual download steps:")
        print("1. Create directory if it doesn't exist:")
        print(f"   mkdir -p {self.data_dir}")
        print("2. Download using curl or wget:")
        print("   curl -o urlhaus_urls.txt https://urlhaus.abuse.ch/downloads/text/")
        print("3. Move files to the data directory:")
        print(f"   mv urlhaus_urls.txt {self.data_dir}/")
        print("="*80)
