import re
import os
import getpass
import logging
import sqlite3
import argparse
import csv
import sys
import json
from datetime import datetime
from pathlib import Path
from remote import RemoteManager
from reputation import create_reputation_manager, ReputationManager
from attack_detection import create_detection_engine
# Set up logging for this module
logger = logging.getLogger(__name__)

# Import platform-specific modules
if sys.platform.startswith('linux'):
    import nix_browsers as browsers
elif sys.platform.startswith('win'):
    import win_browsers as browsers
else:
    print(f"Unsupported platform: {sys.platform}")
    sys.exit(1)

class BrowserExtractorApp:
    """Main application class for browser artifact extraction"""
    def __init__(self):
        """Initialize the application"""
        self.parser = self._init_menu()
        self.args = None
        self.user = None
        self.browser = None
        self.output_dir = None
        self.vt_api = None
        self.haus_api = None
        self.mbl_filepath = None
        self.available_browsers = None
        self.os = None
        self.reputation_manager = None
        self.detection_engine = None
    def _init_menu(self):
        """Initialize the command line parameter menu."""
        menu_parser = argparse.ArgumentParser()
        menu_parser.add_argument("-u", "--user", metavar='',
                               help="""
                               Specifies the user that you want to collect data on. 
                               If all users, enter 'all'
                               """)
        menu_parser.add_argument("-lb", "--listBrowser", action='store_true',
                               help="Lists available browsers installed.")
        menu_parser.add_argument("-b", "--browser", metavar='',
                               help="""
                               Specifies which browser to search. If all installed 
                               browsers, enter 'all'.
                               """)
        menu_parser.add_argument("-v", "--verbose", action='store_true',
                                help="Enable verbose logging output")
        
        # Output control group
        output_group = menu_parser.add_argument_group('Output Control')
        output_group.add_argument("-o", "--output", metavar='',
                                help="Directory path for output files")
        output_group.add_argument("-s", "--summary", action='store_true',
                                help="Generate a summary CSV with all browser activity")
        output_group.add_argument("--format", choices=['csv', 'json'], default='csv',
                                help="Output format (default: csv)")
        output_group.add_argument("--split-artifacts", action='store_true',
                                help="Split each artifact type into separate files")
        
        # Reputation use group
        api_group = menu_parser.add_argument_group('Reputation Lookup')
        api_group.add_argument("-ar", "--allRep", action='store_true',
                            help="""Use all supported services (VirusTotal + URLhaus). 
                            Will be prompted to enter VirusTotal API key.
                            """)
        api_group.add_argument("-vt", "--virusTotal", action='store_true',
                            help="""
                            Specify to use VirusTotal API. Will be prompted to enter API.
                            """)
        api_group.add_argument("-uh", "--urlHaus", action='store_true',
                            help="""
                            Enable URLhaus threat feed checking (uses local downloaded feeds).
                            No API key required.
                            """)
        menu_parser.add_argument("-m", "--mbl", metavar='',
                               help="""
                               Specify to check local MBL for entries. Include file path to
                               local MBL CSV.
                               """)
        
        # Remote execution group
        remote_group = menu_parser.add_argument_group('Remote Execution')
        remote_group.add_argument("-r", "--remote", metavar='',
                                help="Remote host (IP address or hostname) to connect to")
        remote_group.add_argument("-rU", "--remoteUser", metavar='',
                                help="Username for remote authentication")
        
        # Detection engine group
        detection_group = menu_parser.add_argument_group('Threat Detection')
        detection_group.add_argument("-d", "--detect", action='store_true',
                                    help="Enable threat detection engine for attack pattern analysis")
        detection_group.add_argument("--detect-all", action='store_true',
                                    help="Enable all detection categories (XSS, SQLi, CSRF, phishing, malware, C2, social engineering)")
        detection_group.add_argument("--detect-web-attacks", action='store_true',
                                    help="Enable web attack detection (XSS, SQLi, CSRF)")
        detection_group.add_argument("--detect-malware", action='store_true',
                                    help="Enable malware and C2 communication detection")
        detection_group.add_argument("--detect-phishing", action='store_true',
                                    help="Enable phishing and social engineering detection")
        # Enhanced warning in help text
        menu_parser.epilog = """
        DETECTION ENGINE WARNING:
        The threat detection engine looks for obvious signs of attacks and threats using
        pattern-based analysis. It may produce false positives and should not be considered
        a comprehensive security analysis. Always verify findings and correlate with other
        security tools.

        Detection categories include:
        - Web Attacks: XSS, SQL Injection, CSRF (basic pattern matching)
        - Phishing: Typosquatting domains, suspicious URL patterns  
        - Malware: Suspicious file downloads, C2 communication patterns
        - Social Engineering: Urgency keywords, account suspension tactics

        OUTPUT FILES:
        The tool generates multiple output files when detections are enabled:
        - Main artifact files: browser_artifacts_[timestamp].csv/json
        - Summary file: browser_summary_[timestamp].csv/json (if -s used)
        - Threat report: threat_report_[timestamp].csv/json (if threats found)
        - Detailed threat report: detailed_threat_report_[timestamp].csv/json

        EXAMPLE USAGE:
        # Basic extraction with all detections
        python browsertriage.py -u student -b all --detect-all
        
        # Remote extraction with web attack detection and VirusTotal
        python browsertriage.py -r 192.168.1.100 -rU admin -u student -b chrome --detect-web-attacks -vt
        
        # Comprehensive analysis with all services
        python browsertriage.py -u all -b all --detect-all -ar -s --format json
        """
        return menu_parser

    # Add a method to display detection statistics
    def print_detection_statistics(self):
        """Print detailed detection engine statistics."""
        if not self.detection_engine:
            return
        stats = self.detection_engine.get_detection_summary()
        print(f"\n" + "="*60)
        print("THREAT DETECTION STATISTICS")
        print("="*60)
        print(f"URLs analyzed: {stats['statistics']['total_urls_analyzed']}")
        print(f"Total detections: {stats['statistics']['total_detections']}")
        print(f"High/Critical risk: {stats['high_risk_count']}")
        print(f"Medium risk: {stats['medium_risk_count']}")
        print(f"Low risk: {stats['low_risk_count']}")
        if stats['statistics']['detections_by_type']:
            print(f"\nDetection breakdown:")
            for detection_type, count in stats['statistics']['detections_by_type'].items():
                print(f"  {detection_type}: {count}")
        print("="*60)
    
    def parse_args(self):
        """Parse command line arguments and set up application state"""
        self.args = self.parser.parse_args()
        self.os = sys.platform
        # Handle the list browsers option first - simple exit case
        if self.args.listBrowser:
            extractor = browsers.BrowserExtractor()
            available_browsers = extractor.get_available_browsers()
            print(f"Available browsers: {available_browsers}")
            sys.exit(0)
        # Set basic args 
        self.output_dir = self.args.output
        self.user = self.args.user
        self.browser = self.args.browser
        self._configure_logging()
        # Initialize flags
        self.vt_api = None
        self.urlhaus_enabled = False
        # Handle API arguments
        if self.args.allRep:
            # Get VirusTotal API with warning about free tier
            print("\n" + "="*80)
            print("VIRUSTOTAL FREE API CONFIGURATION")
            print("="*80)
            print("You are configuring VirusTotal with the FREE API tier.")
            print("Rate limit: 4 requests per minute (15 second intervals)")
            print("For large numbers of URLs, this will take significant time.")
            print("="*80)
            self.vt_api = input('Enter VirusTotal API key (or press Enter to skip): ').strip()
            if not self.vt_api:
                self.vt_api = None
                print("Skipping VirusTotal - continuing with URLhaus only.")
            # Enable URLhaus when using allRep
            self.urlhaus_enabled = True
            print("URLhaus threat feeds enabled (no API key required)")
        elif self.args.urlHaus:
            # Only URLhaus requested
            self.urlhaus_enabled = True
            print("URLhaus threat feeds enabled (no API key required)")
        elif self.args.virusTotal:
            # Only VirusTotal requested
            print("\n" + "="*80)
            print("VIRUSTOTAL FREE API CONFIGURATION")
            print("="*80)
            print("You are configuring VirusTotal with the FREE API tier.")
            print("Rate limit: 4 requests per minute (15 second intervals)")
            print("For large numbers of URLs, this will take significant time.")
            print("="*80)
            self.vt_api = input('Enter VirusTotal API key: ').strip()
            if not self.vt_api:
                print("Error: VirusTotal API key is required when using -vt option")
                sys.exit(1)
        # Handle MBL path
        if self.args.mbl:
            self.mbl_filepath = Path(self.args.mbl)
        # Initialize reputation services based on provided configuration
        self._setup_reputation_services()
         # Handle detection options
        detection_enabled = (self.args.detect or self.args.detect_all or 
                            self.args.detect_web_attacks or self.args.detect_malware or 
                            self.args.detect_phishing)
        if detection_enabled:
            logger.info("Initializing threat detection engine...")
            self.detection_engine = create_detection_engine()
            if self.args.detect_all:
                logger.info("All detection categories enabled")
            else:
                enabled_categories = []
                if self.args.detect_web_attacks:
                    enabled_categories.append("Web Attacks (XSS, SQLi, CSRF)")
                if self.args.detect_malware:
                    enabled_categories.append("Malware/C2 Communication")
                if self.args.detect_phishing:
                    enabled_categories.append("Phishing/Social Engineering")
                logger.info(f"Detection categories enabled: {', '.join(enabled_categories)}")
            # Show warning about detection limitations
            print("\n" + "="*80)
            print("THREAT DETECTION ENGINE WARNING")
            print("="*80)
            print("The threat detection engine performs pattern-based analysis and may produce")
            print("false positives. It looks for obvious signs of attacks and suspicious patterns.")
            print("This should not be considered a comprehensive security analysis.")
            print("Always verify findings and correlate with other security tools.")
            print("="*80)
        else:
            logger.info("Threat detection engine disabled")
            self.detection_engine = None

    def _setup_reputation_services(self):
        """Initialize reputation services based on provided configuration."""
        services_to_configure = []
        # Check which services are explicitly requested
        if hasattr(self, 'vt_api') and self.vt_api:
            services_to_configure.append('VirusTotal')
        if hasattr(self, 'urlhaus_enabled') and self.urlhaus_enabled:
            services_to_configure.append('URLhaus')
        if hasattr(self, 'mbl_filepath') and self.mbl_filepath:
            services_to_configure.append('LocalMBL')
        if services_to_configure:
            logger.info(f"Setting up URL reputation services: {', '.join(services_to_configure)}")
            # Create reputation manager
            self.reputation_manager = ReputationManager()
            # Add only the requested services
            if 'VirusTotal' in services_to_configure:
                from reputation.api_reputation import VirusTotalService
                vt_service = VirusTotalService(self.vt_api)
                self.reputation_manager.add_service(vt_service, "VirusTotal")
                logger.info("VirusTotal service configured (FREE tier - 4 requests/minute)")
            if 'URLhaus' in services_to_configure:
                from reputation.local_reputation import URLhausService
                logger.info("Setting up URLhaus threat feeds...")
                uh_service = URLhausService(auto_download=True)  # Enable auto-download
                # Debug: Check if service is configured
                logger.info(f"URLhaus service configured: {uh_service.is_configured()}")
                if hasattr(uh_service, 'get_feed_info'):
                    feed_info = uh_service.get_feed_info()
                    logger.info(f"URLhaus feed info: {feed_info}")
                self.reputation_manager.add_service(uh_service, "URLhaus")
                logger.info("URLhaus service configured (local threat feeds)")
            if 'LocalMBL' in services_to_configure:
                from reputation.local_reputation import LocalMBLService
                mbl_service = LocalMBLService(self.mbl_filepath)
                self.reputation_manager.add_service(mbl_service, "LocalMBL")
                logger.info(f"Local MBL service configured with file: {self.mbl_filepath}")
            configured_services = self.reputation_manager.get_configured_services()
            logger.info(f"Successfully configured reputation services: {', '.join(configured_services)}")
        else:
            logger.info("No reputation services requested")
            
    def _configure_logging(self):
        """Configure logging level based on verbose flag."""
        if self.args.verbose:
            # Verbose mode - show all logging
            log_level = logging.DEBUG
            log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        else:
            # Normal mode - show only INFO and above, with simple format
            log_level = logging.INFO
            log_format = '%(message)s'
        # Remove existing handlers
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        # Configure new logging
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=[logging.StreamHandler()]
        )
        # Set specific logger levels for your modules
        if not self.args.verbose:
            # In normal mode, set remote modules to WARNING to reduce noise
            logging.getLogger('remote').setLevel(logging.WARNING)
            logging.getLogger('pypsrp').setLevel(logging.WARNING)
            # Set browser modules to INFO for important messages
            logging.getLogger('Browser').setLevel(logging.INFO)

    def enhance_data_with_reputation(self, extracted_data):
        """
        Enhance extracted browser data with URL reputation information.
        Args:
            extracted_data: Dictionary containing browser artifact data
        Returns:
            Enhanced data with reputation information
        """
        if not self.reputation_manager:
            logger.info("No reputation services configured, skipping URL analysis")
            return extracted_data
        logger.info("Analyzing URLs for reputation information...")
        # Collect all unique URLs from the extracted data
        all_urls = set()
        # Process the nested data structure
        for user, user_browsers in extracted_data.items():
            for browser, browser_data in user_browsers.items():
                # Extract URLs from history
                for history_entry in browser_data.get('history', []):
                    if history_entry.get('url'):
                        all_urls.add(history_entry['url'])
                # Extract URLs from downloads
                for download_entry in browser_data.get('downloads', []):
                    if download_entry.get('source_url'):
                        all_urls.add(download_entry['source_url'])
                    if download_entry.get('original_url'):
                        all_urls.add(download_entry['original_url'])
        logger.info(f"Found {len(all_urls)} unique URLs to analyze")
        if not all_urls:
            logger.info("No URLs found for reputation analysis")
            return extracted_data
        # Use the new batch checking method with VirusTotal confirmation
        url_reputation_results = self.reputation_manager.check_urls_batch_with_confirmation(list(all_urls))
        # Process results into a flat dictionary for easier lookup
        flat_results = {}
        for url, service_results in url_reputation_results.items():
            # Get consensus result for this URL
            consensus_result = self.reputation_manager.get_consensus_result(url)
            flat_results[url] = consensus_result
            # Log suspicious/malicious URLs
            if consensus_result.is_malicious:
                logger.warning(f"MALICIOUS URL detected: {url} (Risk: {consensus_result.get_risk_level()})")
            elif consensus_result.is_suspicious:
                logger.warning(f"SUSPICIOUS URL detected: {url} (Risk: {consensus_result.get_risk_level()})")
        # Now enhance the original data with reputation results
        for user, user_browsers in extracted_data.items():
            for browser, browser_data in user_browsers.items():
                # Enhance history entries
                for history_entry in browser_data.get('history', []):
                    url = history_entry.get('url')
                    if url and url in flat_results:
                        reputation_result = flat_results[url]
                        history_entry['reputation'] = {
                            'risk_level': reputation_result.get_risk_level(),
                            'is_malicious': reputation_result.is_malicious,
                            'is_suspicious': reputation_result.is_suspicious,
                            'confidence_score': reputation_result.confidence_score,
                            'threat_types': reputation_result.threat_types,
                            'categories': reputation_result.categories,
                            'services_checked': list(reputation_result.additional_info.get('service_results', {}).keys()) if reputation_result.additional_info else []
                        }
                # Enhance download entries
                for download_entry in browser_data.get('downloads', []):
                    # Check source URL
                    source_url = download_entry.get('source_url')
                    if source_url and source_url in flat_results:
                        reputation_result = flat_results[source_url]
                        download_entry['source_reputation'] = {
                            'risk_level': reputation_result.get_risk_level(),
                            'is_malicious': reputation_result.is_malicious,
                            'is_suspicious': reputation_result.is_suspicious,
                            'confidence_score': reputation_result.confidence_score,
                            'threat_types': reputation_result.threat_types,
                            'categories': reputation_result.categories
                        }
                    # Check original URL if different
                    original_url = download_entry.get('original_url')
                    if original_url and original_url != source_url and original_url in flat_results:
                        reputation_result = flat_results[original_url]
                        download_entry['original_reputation'] = {
                            'risk_level': reputation_result.get_risk_level(),
                            'is_malicious': reputation_result.is_malicious,
                            'is_suspicious': reputation_result.is_suspicious,
                            'confidence_score': reputation_result.confidence_score,
                            'threat_types': reputation_result.threat_types,
                            'categories': reputation_result.categories
                        }
        # Generate summary statistics
        malicious_count = sum(1 for result in flat_results.values() if result.is_malicious)
        suspicious_count = sum(1 for result in flat_results.values() if result.is_suspicious)
        logger.info(f"URL Reputation Analysis Complete:")
        logger.info(f"  Total URLs analyzed: {len(all_urls)}")
        logger.info(f"  Malicious URLs found: {malicious_count}")
        logger.info(f"  Suspicious URLs found: {suspicious_count}")
        logger.info(f"  Clean URLs: {len(all_urls) - malicious_count - suspicious_count}")
        return extracted_data

    def handle_extraction(self):
        """Handle the extraction based on user and browser selection"""
        # Get the browser selection
        browser_to_extract = None
        if self.args.browser and self.args.browser.lower() != 'all':
            browser_to_extract = self.args.browser.lower()
            # Verify the browser exists
            extractor = browsers.BrowserExtractor()
            available_browsers = extractor.get_available_browsers()
            if browser_to_extract not in available_browsers:
                print(f"Error: Browser '{browser_to_extract}' not found. Available browsers: {available_browsers}")
                sys.exit(1)
        # Handle user selection
        if self.args.user and self.args.user.lower() == 'all':
            # Extract from all users
            extractor = browsers.BrowserExtractor()
            return extractor.extract_from_all_users(browser_to_extract)
        else:
            # Single user extraction
            extractor = browsers.BrowserExtractor(target_user=self.args.user)
            if browser_to_extract:
                # Extract from a specific browser for this user
                browser_data = extractor.extract_single_browser(browser_to_extract)
                return {self.args.user: {browser_to_extract: browser_data}}
            else:
                # Extract from all browsers for this user
                all_browser_data = extractor.extract_from_all_browsers()
                return {self.args.user: all_browser_data}
    
    def run(self):
        """Run the main application logic"""
        self.parse_args()
        # Basic error checking
        if not self.user:
            print("Error: User must be specified with -u/--user")
            sys.exit(1)
        if not self.browser:
            print("Error: Browser must be specified with -b/--browser")
            sys.exit(1)
        # Handle remote extraction
        if self.args.remote:
            if not self.args.remoteUser:
                print("Error: Remote username must be provided with -rU/--remoteUser")
                sys.exit(1)
            # Use getpass for secure password input
            remote_pass = getpass.getpass(f"Enter password for {self.args.remoteUser}@{self.args.remote}: ")
            print(f"Connecting to remote host: {self.args.remote}")
            # Initialize remote manager
            remote_mgr = RemoteManager()
            # Use the user parameter for both remote authentication and target user
            target_user = self.args.user or 'all'
            # Extract data
            data = remote_mgr.extract(
                hostname=self.args.remote,  # IP address or hostname
                username=self.args.remoteUser,
                password=remote_pass,
                target_user=target_user,
                browser=self.args.browser or 'all'
            )
            if data:
                print("Remote extraction successful")
                print(f"DEBUG: About to enhance data. Reputation manager exists: {self.reputation_manager is not None}")
                # Enhance with reputation data if services are configured
                if self.reputation_manager:
                    data = self.enhance_data_with_reputation(data)
                # Process data here
                self.process_extracted_data(data)
            else:
                print("Remote extraction failed")
            return
        # Handle local extraction
        extraction_data = self.handle_extraction()
        if extraction_data:
            print("Local extraction successful")
            # Show a brief summary instead of dumping all data
            total_entries = 0
            for user, user_data in extraction_data.items():
                for browser, browser_data in user_data.items():
                    total_entries += len(browser_data.get('history', []))
                    total_entries += len(browser_data.get('cookies', []))
                    total_entries += len(browser_data.get('downloads', []))
            print(f"Extracted {total_entries} total artifacts")  # <-- FIXED: Print once outside the loop
            # Enhance with reputation data if services are configured
            if self.reputation_manager:
                extraction_data = self.enhance_data_with_reputation(extraction_data)
            # Process the extracted data
            self.process_extracted_data(extraction_data)
        else:
            print("Local extraction failed")

    def process_extracted_data(self, data):
        """Process and save the extracted data with detection results and user-centric output."""
        print("\nExtraction Summary:")
        # Create output directory if it doesn't exist
        if self.args.output:
            output_dir = Path(self.args.output)
            output_dir.mkdir(parents=True, exist_ok=True)
        else:
            output_dir = Path.cwd()
        # Generate timestamp for file naming
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Track totals for summary
        total_stats = {
            'users': 0,
            'browsers': 0,
            'history_entries': 0,
            'cookie_entries': 0,
            'download_entries': 0,
            'malicious_urls': 0,
            'suspicious_urls': 0,
            'threat_detections': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            },
            'detection_types': {}
        }
        # Prepare data for summary if requested
        summary_data = []
        # Process each user
        for user, user_data in data.items():
            total_stats['users'] += 1
            user_artifacts = []
            print(f"\nUser: {user}")
            for browser, browser_data in user_data.items():
                total_stats['browsers'] += 1
                # Count entries
                history_count = len(browser_data.get('history', []))
                cookie_count = len(browser_data.get('cookies', []))
                download_count = len(browser_data.get('downloads', []))
                total_stats['history_entries'] += history_count
                total_stats['cookie_entries'] += cookie_count
                total_stats['download_entries'] += download_count
                print(f"  Browser: {browser}")
                print(f"    History entries: {history_count}")
                print(f"    Cookie entries: {cookie_count}")
                print(f"    Download entries: {download_count}")
                # Count reputation and detection results
                malicious_history = 0
                suspicious_history = 0
                malicious_downloads = 0
                suspicious_downloads = 0
                # Track threat detections
                browser_detections = {
                    'CRITICAL': 0,
                    'HIGH': 0,
                    'MEDIUM': 0,
                    'LOW': 0
                }
                browser_detection_types = {}
                # Process history entries
                for entry in browser_data.get('history', []):
                    # Add user and browser info for output
                    entry_with_meta = entry.copy()
                    entry_with_meta.update({
                        'user': user,
                        'browser': browser,
                        'artifact_type': 'history'
                    })
                    user_artifacts.append(entry_with_meta)
                    # Check reputation
                    if 'reputation' in entry:
                        if entry['reputation']['is_malicious']:
                            malicious_history += 1
                            total_stats['malicious_urls'] += 1
                        elif entry['reputation']['is_suspicious']:
                            suspicious_history += 1
                            total_stats['suspicious_urls'] += 1
                    # Check threat detections
                    if 'threat_detections' in entry:
                        for detection in entry['threat_detections']:
                            severity = detection['severity']
                            detection_type = detection['type']
                            browser_detections[severity] += 1
                            total_stats['threat_detections'][severity] += 1
                            if detection_type not in browser_detection_types:
                                browser_detection_types[detection_type] = 0
                            browser_detection_types[detection_type] += 1
                            if detection_type not in total_stats['detection_types']:
                                total_stats['detection_types'][detection_type] = 0
                            total_stats['detection_types'][detection_type] += 1
                    # Add to summary
                    if self.args.summary:
                        threat_info = ""
                        if 'threat_detections' in entry:
                            threat_types = [d['type'] for d in entry['threat_detections']]
                            threat_info = "; ".join(threat_types)
                        summary_data.append({
                            'user': user,
                            'browser': browser,
                            'artifact_type': 'history',
                            'url': entry.get('url', ''),
                            'title': entry.get('title', ''),
                            'timestamp': entry.get('visit_time', ''),
                            'visit_count': entry.get('visit_count', ''),
                            'referrer': entry.get('referrer_url', ''),
                            'reputation_risk': entry.get('reputation', {}).get('risk_level', 'UNKNOWN'),
                            'is_malicious': entry.get('reputation', {}).get('is_malicious', False),
                            'is_suspicious': entry.get('reputation', {}).get('is_suspicious', False),
                            'threat_detections': threat_info,
                            'filename': '',
                            'file_size': '',
                            'download_state': ''
                        })
                # Process download entries
                for entry in browser_data.get('downloads', []):
                    entry_with_meta = entry.copy()
                    entry_with_meta.update({
                        'user': user,
                        'browser': browser,
                        'artifact_type': 'downloads'
                    })
                    user_artifacts.append(entry_with_meta)
                    # Check reputation
                    if 'source_reputation' in entry:
                        if entry['source_reputation']['is_malicious']:
                            malicious_downloads += 1
                            total_stats['malicious_urls'] += 1
                        elif entry['source_reputation']['is_suspicious']:
                            suspicious_downloads += 1
                            total_stats['suspicious_urls'] += 1
                    # Check threat detections
                    if 'threat_detections' in entry:
                        for detection in entry['threat_detections']:
                            severity = detection['severity']
                            detection_type = detection['type']
                            browser_detections[severity] += 1
                            total_stats['threat_detections'][severity] += 1
                            if detection_type not in browser_detection_types:
                                browser_detection_types[detection_type] = 0
                            browser_detection_types[detection_type] += 1
                            if detection_type not in total_stats['detection_types']:
                                total_stats['detection_types'][detection_type] = 0
                            total_stats['detection_types'][detection_type] += 1
                    # Add to summary
                    if self.args.summary:
                        threat_info = ""
                        if 'threat_detections' in entry:
                            threat_types = [d['type'] for d in entry['threat_detections']]
                            threat_info = "; ".join(threat_types)
                        summary_data.append({
                            'user': user,
                            'browser': browser,
                            'artifact_type': 'downloads',
                            'url': entry.get('source_url', ''),
                            'title': '',
                            'timestamp': entry.get('start_time', ''),
                            'visit_count': '',
                            'referrer': '',
                            'reputation_risk': entry.get('source_reputation', {}).get('risk_level', 'UNKNOWN'),
                            'is_malicious': entry.get('source_reputation', {}).get('is_malicious', False),
                            'is_suspicious': entry.get('source_reputation', {}).get('is_suspicious', False),
                            'threat_detections': threat_info,
                            'filename': entry.get('filename', ''),
                            'file_size': entry.get('size_bytes', ''),
                            'download_state': entry.get('state', '')
                        })
                # Process cookie entries
                for entry in browser_data.get('cookies', []):
                    entry_with_meta = entry.copy()
                    entry_with_meta.update({
                        'user': user,
                        'browser': browser,
                        'artifact_type': 'cookies'
                    })
                    user_artifacts.append(entry_with_meta)
                # Show security alerts for this browser
                has_reputation_alerts = (malicious_history > 0 or suspicious_history > 0 or 
                                    malicious_downloads > 0 or suspicious_downloads > 0)
                has_detection_alerts = any(count > 0 for count in browser_detections.values())
                if has_reputation_alerts or has_detection_alerts:
                    print(f"    🚨 SECURITY ALERTS:")
                    # Reputation alerts
                    if malicious_history > 0:
                        print(f"      🔴 Malicious history URLs: {malicious_history}")
                    if suspicious_history > 0:
                        print(f"      🟡 Suspicious history URLs: {suspicious_history}")
                    if malicious_downloads > 0:
                        print(f"      🔴 Malicious download URLs: {malicious_downloads}")
                    if suspicious_downloads > 0:
                        print(f"      🟡 Suspicious download URLs: {suspicious_downloads}")
                    # Threat detection alerts
                    if browser_detections['CRITICAL'] > 0:
                        print(f"      💀 CRITICAL threats detected: {browser_detections['CRITICAL']}")
                    if browser_detections['HIGH'] > 0:
                        print(f"      🔴 HIGH risk threats: {browser_detections['HIGH']}")
                    if browser_detections['MEDIUM'] > 0:
                        print(f"      🟠 MEDIUM risk threats: {browser_detections['MEDIUM']}")
                    if browser_detections['LOW'] > 0:
                        print(f"      🟡 LOW risk threats: {browser_detections['LOW']}")
                    # Show detection types
                    if browser_detection_types:
                        detection_summary = ", ".join([f"{dtype}: {count}" for dtype, count in browser_detection_types.items()])
                        print(f"      Threat types: {detection_summary}")
            # Save per-user file
            if self.args.user.lower() == 'all':
                # Individual files for each user when extracting all users
                self._save_user_data(user_artifacts, user, output_dir, timestamp)
            else:
                # Single file when extracting specific user
                self._save_user_data(user_artifacts, user, output_dir, timestamp)
        # Save summary file if requested
        if self.args.summary and summary_data:
            self._save_summary_data(summary_data, output_dir, timestamp)
        # Print overall summary
        print(f"\n" + "="*80)
        print("OVERALL EXTRACTION SUMMARY")
        print("="*80)
        print(f"Total users processed: {total_stats['users']}")
        print(f"Total browser instances: {total_stats['browsers']}")
        print(f"Total history entries: {total_stats['history_entries']}")
        print(f"Total cookie entries: {total_stats['cookie_entries']}")
        print(f"Total download entries: {total_stats['download_entries']}")
        # Reputation analysis summary
        if self.reputation_manager:
            print(f"\nURL REPUTATION ANALYSIS:")
            print(f"🔴 Malicious URLs found: {total_stats['malicious_urls']}")
            print(f"🟡 Suspicious URLs found: {total_stats['suspicious_urls']}")
            clean_urls = (total_stats['history_entries'] + total_stats['download_entries'] - 
                        total_stats['malicious_urls'] - total_stats['suspicious_urls'])
            print(f"🟢 Clean URLs: {clean_urls}")
        # Threat detection summary
        if self.detection_engine:
            total_detections = sum(total_stats['threat_detections'].values())
            print(f"\nTHREAT DETECTION ANALYSIS:")
            print(f"Total threats detected: {total_detections}")
            if total_stats['threat_detections']['CRITICAL'] > 0:
                print(f"💀 CRITICAL threats: {total_stats['threat_detections']['CRITICAL']}")
            if total_stats['threat_detections']['HIGH'] > 0:
                print(f"🔴 HIGH risk threats: {total_stats['threat_detections']['HIGH']}")
            if total_stats['threat_detections']['MEDIUM'] > 0:
                print(f"🟠 MEDIUM risk threats: {total_stats['threat_detections']['MEDIUM']}")
            if total_stats['threat_detections']['LOW'] > 0:
                print(f"🟡 LOW risk threats: {total_stats['threat_detections']['LOW']}")
            if total_stats['detection_types']:
                print(f"\nThreat Types Detected:")
                for detection_type, count in total_stats['detection_types'].items():
                    print(f"  {detection_type}: {count}")
        print(f"="*80)

    def _save_user_data(self, user_artifacts, user, output_dir, timestamp):
        """Save user-specific artifact data to file."""
        if not user_artifacts:
            print(f"No artifacts found for user {user}")
            return
        # Generate filename
        safe_user = user.replace(' ', '_').replace('/', '_')
        filename = f"browser_artifacts_{safe_user}_{timestamp}.{self.args.format}"
        filepath = output_dir / filename
        # Write the data
        self._write_data_file(user_artifacts, filepath)
        print(f"Saved artifacts for user {user}: {filepath}")

    def _write_data_file(self, data, filepath):
        """Write data to file in the specified format with enhanced threat detection support and URL preservation."""
        if not data:
            print(f"No data to save to {filepath}")
            return
        if self.args.format == 'json':
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        else:  # CSV format
            # Get all unique keys from the data, including flattened threat detection data
            all_keys = set()
            processed_data = []
            for item in data:
                processed_item = item.copy()
                # Flatten threat detection data for CSV
                if 'threat_detections' in processed_item:
                    detections = processed_item['threat_detections']
                    if isinstance(detections, list) and detections:
                        # Get the most severe detection for primary columns
                        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
                        most_severe = max(detections, key=lambda d: severity_order.get(d['severity'], 0))
                        processed_item['threat_severity'] = most_severe['severity']
                        processed_item['threat_type'] = most_severe['type']
                        processed_item['threat_confidence'] = most_severe['confidence']
                        processed_item['threat_description'] = most_severe['description']
                        processed_item['threat_mitigation'] = most_severe.get('mitigation', '')
                        # Count detections by severity
                        severity_counts = {}
                        for detection in detections:
                            sev = detection['severity']
                            severity_counts[sev] = severity_counts.get(sev, 0) + 1
                        processed_item['threat_critical_count'] = severity_counts.get('CRITICAL', 0)
                        processed_item['threat_high_count'] = severity_counts.get('HIGH', 0)
                        processed_item['threat_medium_count'] = severity_counts.get('MEDIUM', 0)
                        processed_item['threat_low_count'] = severity_counts.get('LOW', 0)
                        # All detection types as a comma-separated string
                        detection_types = list(set(d['type'] for d in detections))
                        processed_item['all_threat_types'] = ', '.join(detection_types)
                        # FIXED: Keep full evidence text to preserve URLs
                        evidence_text = []
                        for detection in detections:
                            if detection.get('evidence'):
                                for evidence in detection['evidence']:
                                    evidence_text.append(str(evidence))
                        processed_item['threat_evidence'] = '; '.join(evidence_text)
                    else:
                        # No detections
                        processed_item['threat_severity'] = ''
                        processed_item['threat_type'] = ''
                        processed_item['threat_confidence'] = ''
                        processed_item['threat_description'] = ''
                        processed_item['threat_mitigation'] = ''
                        processed_item['threat_critical_count'] = 0
                        processed_item['threat_high_count'] = 0
                        processed_item['threat_medium_count'] = 0
                        processed_item['threat_low_count'] = 0
                        processed_item['all_threat_types'] = ''
                        processed_item['threat_evidence'] = ''
                    # Remove the original nested structure for CSV
                    del processed_item['threat_detections']
                # Flatten reputation data for CSV if present
                if 'reputation' in processed_item and isinstance(processed_item['reputation'], dict):
                    rep = processed_item['reputation']
                    processed_item['reputation_risk_level'] = rep.get('risk_level', '')
                    processed_item['reputation_is_malicious'] = rep.get('is_malicious', False)
                    processed_item['reputation_is_suspicious'] = rep.get('is_suspicious', False)
                    processed_item['reputation_confidence'] = rep.get('confidence_score', '')
                    processed_item['reputation_threat_types'] = ', '.join(rep.get('threat_types', []))
                    processed_item['reputation_categories'] = ', '.join(rep.get('categories', []))
                    processed_item['reputation_services'] = ', '.join(rep.get('services_checked', []))
                    # Remove the original nested structure for CSV
                    del processed_item['reputation']
                # Handle other nested structures similarly - PRESERVE LONG FIELDS
                for key, value in list(processed_item.items()):
                    if isinstance(value, dict):
                        # Convert dict to string representation for CSV but don't truncate
                        processed_item[f"{key}_json"] = json.dumps(value, ensure_ascii=False)
                        del processed_item[key]
                    elif isinstance(value, list) and value and isinstance(value[0], dict):
                        # Convert list of dicts to string representation for CSV but don't truncate
                        processed_item[f"{key}_json"] = json.dumps(value, ensure_ascii=False)
                        del processed_item[key]
                processed_data.append(processed_item)
                all_keys.update(processed_item.keys())
            # Define column order for better readability
            priority_columns = [
                'user', 'browser', 'artifact_type', 'url', 'title', 'timestamp', 'filename',
                'threat_severity', 'threat_type', 'threat_confidence', 'all_threat_types',
                'reputation_risk_level', 'reputation_is_malicious', 'reputation_is_suspicious',
                'threat_evidence'  # Add evidence column to priority
            ]
            # Create ordered field list
            ordered_fields = []
            for col in priority_columns:
                if col in all_keys:
                    ordered_fields.append(col)
                    all_keys.remove(col)
            # Add remaining fields alphabetically
            ordered_fields.extend(sorted(all_keys))
            # Write to CSV with proper handling for long URLs and text
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                # FIXED: Use QUOTE_MINIMAL and increase field size limit
                csv.field_size_limit(10485760)  # 10MB field size limit
                writer = csv.DictWriter(f, fieldnames=ordered_fields, quoting=csv.QUOTE_MINIMAL)
                writer.writeheader()
                writer.writerows(processed_data)

    def _save_summary_data(self, summary_data, output_dir, timestamp):
        """Save the consolidated summary data with threat detection information."""
        filename = f"browser_summary_{timestamp}.{self.args.format}"
        filepath = output_dir / filename
        self._write_data_file(summary_data, filepath)
        print(f"\nSaved summary data: {filepath}")
        # If threat detections were found, create a separate threat-only report
        threat_data = [entry for entry in summary_data 
                    if entry.get('threat_detections') or 
                        entry.get('is_malicious') or 
                        entry.get('is_suspicious')]
        if threat_data:
            threat_filename = f"threat_report_{timestamp}.{self.args.format}"
            threat_filepath = output_dir / threat_filename
            self._write_data_file(threat_data, threat_filepath)
            print(f"Saved threat-specific report: {threat_filepath}")

    def generate_detection_report(self, data, output_dir, timestamp):
        """Generate a dedicated threat detection report."""
        if not self.detection_engine:
            return 0
        detection_summary = []
        for user, user_data in data.items():
            for browser, browser_data in user_data.items():
                # Process history detections
                for entry in browser_data.get('history', []):
                    if 'threat_detections' in entry:
                        for detection in entry['threat_detections']:
                            # Safe handling of evidence and references
                            evidence_list = detection.get('evidence', [])
                            if evidence_list is None:
                                evidence_list = []
                            references_list = detection.get('references', [])
                            if references_list is None:
                                references_list = []
                            # FIXED: Don't truncate URLs in evidence
                            full_evidence = '; '.join(str(e) for e in evidence_list if e)
                            detection_summary.append({
                                'user': user,
                                'browser': browser,
                                'artifact_type': 'history',
                                'url': entry.get('url', ''),  # Full URL
                                'title': entry.get('title', ''),
                                'visit_time': entry.get('visit_time', ''),
                                'threat_type': detection.get('type', ''),
                                'severity': detection.get('severity', ''),
                                'confidence': detection.get('confidence', 0),
                                'description': detection.get('description', ''),
                                'mitigation': detection.get('mitigation', ''),
                                'evidence': full_evidence,  # Full evidence text
                                'references': '; '.join(str(r) for r in references_list if r)
                            })
                # Process download detections
                for entry in browser_data.get('downloads', []):
                    if 'threat_detections' in entry:
                        for detection in entry['threat_detections']:
                            # Safe handling of evidence and references
                            evidence_list = detection.get('evidence', [])
                            if evidence_list is None:
                                evidence_list = []
                            references_list = detection.get('references', [])
                            if references_list is None:
                                references_list = []
                            # FIXED: Don't truncate URLs in evidence
                            full_evidence = '; '.join(str(e) for e in evidence_list if e)
                            detection_summary.append({
                                'user': user,
                                'browser': browser,
                                'artifact_type': 'downloads',
                                'url': entry.get('source_url', ''),  # Full URL
                                'filename': entry.get('filename', ''),
                                'download_time': entry.get('start_time', ''),
                                'threat_type': detection.get('type', ''),
                                'severity': detection.get('severity', ''),
                                'confidence': detection.get('confidence', 0),
                                'description': detection.get('description', ''),
                                'mitigation': detection.get('mitigation', ''),
                                'evidence': full_evidence,  # Full evidence text
                                'references': '; '.join(str(r) for r in references_list if r)
                            })
        if detection_summary:
            report_filename = f"detailed_threat_report_{timestamp}.{self.args.format}"
            report_filepath = output_dir / report_filename
            self._write_data_file(detection_summary, report_filepath)
            print(f"Saved detailed threat detection report: {report_filepath}")
            return len(detection_summary)
        return 0

    def enhance_data_with_detections(self, extracted_data):
        """
        Enhance extracted browser data with threat detection analysis.
        Args:
            extracted_data: Dictionary containing browser artifact data
        Returns:
            Enhanced data with detection information
        """
        if not self.detection_engine:
            logger.info("Threat detection engine not enabled, skipping detection analysis")
            return extracted_data
        logger.info("Running threat detection analysis on browser artifacts...")
        total_detections = 0
        critical_detections = 0
        high_detections = 0
        medium_detections = 0
        low_detections = 0
        # Process the nested data structure
        for user, user_browsers in extracted_data.items():
            for browser, browser_data in user_browsers.items():
                # Analyze browser artifacts
                detection_results = self.detection_engine.analyze_browser_artifacts(browser_data)
                # Add detection results to history entries
                if 'history' in browser_data and 'history' in detection_results:
                    # Create a mapping of URLs to their detections
                    history_detections_by_url = {}
                    for detection in detection_results['history']:
                        # Find the corresponding history entry by looking for URL in evidence
                        for entry in browser_data['history']:
                            url = entry.get('url', '')
                            if url and any(url in str(evidence) for evidence in detection.evidence):
                                if url not in history_detections_by_url:
                                    history_detections_by_url[url] = []
                                history_detections_by_url[url].append({
                                    'type': detection.detection_type,
                                    'severity': detection.severity,
                                    'confidence': detection.confidence,
                                    'description': detection.description,
                                    'evidence': detection.evidence,
                                    'mitigation': detection.mitigation,
                                    'references': detection.references
                                })
                                break
                    # Add detections to history entries
                    for entry in browser_data['history']:
                        url = entry.get('url', '')
                        if url in history_detections_by_url:
                            entry['threat_detections'] = history_detections_by_url[url]
                            for detection in history_detections_by_url[url]:
                                total_detections += 1
                                if detection['severity'] == 'CRITICAL':
                                    critical_detections += 1
                                elif detection['severity'] == 'HIGH':
                                    high_detections += 1
                                elif detection['severity'] == 'MEDIUM':
                                    medium_detections += 1
                                elif detection['severity'] == 'LOW':
                                    low_detections += 1
                # Add detection results to download entries
                if 'downloads' in browser_data and 'downloads' in detection_results:
                    download_detections_by_filename = {}
                    for detection in detection_results['downloads']:
                        # Find corresponding download entry by looking for filename or URL in evidence
                        for entry in browser_data['downloads']:
                            filename = entry.get('filename', '')
                            source_url = entry.get('source_url', '')
                            # Check if this detection relates to this download
                            detection_relates = False
                            for evidence in detection.evidence:
                                evidence_str = str(evidence)
                                if ((filename and filename in evidence_str) or 
                                    (source_url and source_url in evidence_str)):
                                    detection_relates = True
                                    break
                            if detection_relates:
                                key = f"{source_url}|{filename}"
                                if key not in download_detections_by_filename:
                                    download_detections_by_filename[key] = []
                                download_detections_by_filename[key].append({
                                    'type': detection.detection_type,
                                    'severity': detection.severity,
                                    'confidence': detection.confidence,
                                    'description': detection.description,
                                    'evidence': detection.evidence,
                                    'mitigation': detection.mitigation,
                                    'references': detection.references
                                })
                                break
                    # Add detections to download entries
                    for entry in browser_data['downloads']:
                        filename = entry.get('filename', '')
                        source_url = entry.get('source_url', '')
                        key = f"{source_url}|{filename}"
                        if key in download_detections_by_filename:
                            entry['threat_detections'] = download_detections_by_filename[key]
                            for detection in download_detections_by_filename[key]:
                                total_detections += 1
                                if detection['severity'] == 'CRITICAL':
                                    critical_detections += 1
                                elif detection['severity'] == 'HIGH':
                                    high_detections += 1
                                elif detection['severity'] == 'MEDIUM':
                                    medium_detections += 1
                                elif detection['severity'] == 'LOW':
                                    low_detections += 1
        # Log summary of detections
        logger.info(f"Threat Detection Analysis Complete:")
        logger.info(f"  Total detections: {total_detections}")
        if critical_detections > 0:
            logger.warning(f"  🔴 CRITICAL threats: {critical_detections}")
        if high_detections > 0:
            logger.warning(f"  🟠 HIGH risk threats: {high_detections}")
        if medium_detections > 0:
            logger.info(f"  🟡 MEDIUM risk threats: {medium_detections}")
        if low_detections > 0:
            logger.info(f"  🟢 LOW risk threats: {low_detections}")
        return extracted_data

    def run(self):
        """Run the main application logic"""
        self.parse_args()
        # Basic error checking
        if not self.user:
            print("Error: User must be specified with -u/--user")
            sys.exit(1)
        if not self.browser:
            print("Error: Browser must be specified with -b/--browser")
            sys.exit(1)
        # Handle remote extraction
        if self.args.remote:
            if not self.args.remoteUser:
                print("Error: Remote username must be provided with -rU/--remoteUser")
                sys.exit(1)
            # Use getpass for secure password input
            remote_pass = getpass.getpass(f"Enter password for {self.args.remoteUser}@{self.args.remote}: ")
            print(f"Connecting to remote host: {self.args.remote}")
            # Initialize remote manager
            remote_mgr = RemoteManager()
            # Use the user parameter for both remote authentication and target user
            target_user = self.args.user or 'all'
            # Extract data
            data = remote_mgr.extract(
                hostname=self.args.remote,
                username=self.args.remoteUser,
                password=remote_pass,
                target_user=target_user,
                browser=self.args.browser or 'all'
            )
            if data:
                print("Remote extraction successful")
                # Enhance with reputation data if services are configured
                if self.reputation_manager:
                    data = self.enhance_data_with_reputation(data)
                # Enhance with threat detection if enabled
                if self.detection_engine:
                    data = self.enhance_data_with_detections(data)
                # Process data and generate reports
                self.process_extracted_data(data)
                # Generate additional detection reports if enabled
                if self.detection_engine:
                    output_dir = Path(self.args.output) if self.args.output else Path.cwd()
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    detections_count = self.generate_detection_report(data, output_dir, timestamp)
                    if detections_count > 0:
                        print(f"Generated detailed threat report with {detections_count} detections")
            else:
                print("Remote extraction failed")
            return
        # Handle local extraction
        extraction_data = self.handle_extraction()
        if extraction_data:
            print("Local extraction successful")
            # Show a brief summary instead of dumping all data
            total_entries = 0
            for user, user_data in extraction_data.items():
                for browser, browser_data in user_data.items():
                    total_entries += len(browser_data.get('history', []))
                    total_entries += len(browser_data.get('cookies', []))
                    total_entries += len(browser_data.get('downloads', []))
            print(f"Extracted {total_entries} total artifacts")
            # Enhance with reputation data if services are configured
            if self.reputation_manager:
                extraction_data = self.enhance_data_with_reputation(extraction_data)
            # Enhance with threat detection if enabled
            if self.detection_engine:
                extraction_data = self.enhance_data_with_detections(extraction_data)
            # Process the extracted data
            self.process_extracted_data(extraction_data)
            # Generate additional detection reports if enabled
            if self.detection_engine:
                output_dir = Path(self.args.output) if self.args.output else Path.cwd()
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                detections_count = self.generate_detection_report(extraction_data, output_dir, timestamp)
                if detections_count > 0:
                    print(f"Generated detailed threat report with {detections_count} detections")
        else:
            print("Local extraction failed")

if __name__ == '__main__':
    app = BrowserExtractorApp()
    app.run()