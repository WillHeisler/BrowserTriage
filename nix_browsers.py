import os
import sqlite3
import shutil
import tempfile
from pathlib import Path
import datetime
import logging
import re
from abc import ABC, abstractmethod


# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('Browser')

class BrowserBase(ABC):
    """Abstract base class for extracting browser artifacts on Linux systems."""
    def __init__(self, target_user=None):
        """
        Initialize the browser artifact extractor.
        Args:
            target_user (str, optional): Username to extract data from. Defaults to current user.
        """
        self.target_user = target_user or os.getenv('USER')
        self.browser_name = self.__class__.__name__.replace('Nix', '').lower()
        # Temporary directory for database copies
        self.temp_dir = None
        # To be set by derived classes
        self.history_db_path = None
        self.cookies_db_path = None
        self.temp_history_path = None
        self.temp_cookies_path = None
        # Set up browser-specific paths
        self._setup_browser_paths()
        logger.info(f"Initialized {self.browser_name} extractor for user '{self.target_user}'")
    
    @abstractmethod
    def _setup_browser_paths(self):
        """Set up browser-specific file paths. To be implemented by derived classes."""
        pass
    
    def _setup_temp_files(self):
        """
        Create temporary copies of browser databases.
        Returns:
            bool: True if setup was successful, False otherwise.
        """
        try:
            # Check if databases exist
            if not self.history_db_path or not os.path.exists(self.history_db_path):
                logger.warning(f"{self.browser_name} history database not found at {self.history_db_path}")
                return False
            if not self.cookies_db_path or not os.path.exists(self.cookies_db_path):
                logger.warning(f"{self.browser_name} cookies database not found at {self.cookies_db_path}")
                return False
            # Create temporary directory
            self.temp_dir = tempfile.mkdtemp()
            self.temp_history_path = os.path.join(self.temp_dir, f"{self.browser_name}_history")
            self.temp_cookies_path = os.path.join(self.temp_dir, f"{self.browser_name}_cookies")
            # Copy files (browsers lock the original files when running)
            shutil.copy2(self.history_db_path, self.temp_history_path)
            shutil.copy2(self.cookies_db_path, self.temp_cookies_path)
            logger.info(f"Created temporary copies of {self.browser_name} databases")
            return True
        except Exception as e:
            logger.error(f"Error setting up temporary files for {self.browser_name}: {e}")
            return False
    
    def _cleanup_temp_files(self):
        """Clean up temporary files and directories."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            logger.info(f"Cleaned up temporary files for {self.browser_name}")
    
    @abstractmethod
    def extract_history_with_referrers(self):
        """
        Extract browser history with referrer URLs.
        Returns:
            List[Dict[str, Any]]: List of history entries with referrer information.
        """
        pass
    
    @abstractmethod
    def extract_cookies(self):
        """
        Extract browser cookies.
        Returns:
            List[Dict[str, Any]]: List of cookie entries.
        """
        pass
    
    def get_browser_info(self):
        """
        Get information about the browser installation.
        Returns:
            Dict[str, Any]: Browser information
        """
        info = {
            'browser_name': self.browser_name,
            'history_db_path': str(self.history_db_path) if self.history_db_path else None,
            'cookies_db_path': str(self.cookies_db_path) if self.cookies_db_path else None,
            'installed': self.is_installed(),
            'user': self.target_user
        }
        return info
    
    def is_installed(self):
        """
        Check if the browser is installed.
        Returns:
            bool: True if browser databases are found, False otherwise
        """
        history_exists = self.history_db_path and os.path.exists(self.history_db_path)
        cookies_exists = self.cookies_db_path and os.path.exists(self.cookies_db_path)
        return history_exists and cookies_exists
    
    @abstractmethod
    def extract_downloads(self):
        """
        Extract browser download history.
        Returns:
            List[Dict[str, Any]]: List of download entries
        """
        pass

    def extract_all_artifacts(self):
        """
        Extract all browser artifacts (history, cookies, downloads).
        Returns:
            Dict[str, List[Dict[str, Any]]]: Dictionary with artifact types as keys
        """
        # Setup temporary files
        if not self._setup_temp_files():
            return {'history': [], 'cookies': [], 'downloads': []}
        try:
            # Extract history with referrers
            history_data = self.extract_history_with_referrers()
            logger.info(f"Extracted {len(history_data)} history entries from {self.browser_name}")
            # Extract cookies
            cookies_data = self.extract_cookies()
            logger.info(f"Extracted {len(cookies_data)} cookies from {self.browser_name}")
            # Extract downloads
            downloads_data = self.extract_downloads()
            logger.info(f"Extracted {len(downloads_data)} downloads from {self.browser_name}")
            return {
                'history': history_data,
                'cookies': cookies_data,
                'downloads': downloads_data
            }
        except Exception as e:
            logger.error(f"Error extracting {self.browser_name} artifacts: {e}")
            return {'history': [], 'cookies': [], 'downloads': []}
        finally:
            # Clean up temporary files
            self._cleanup_temp_files()

class Chrome(BrowserBase):
    """Class for extracting Chrome browser artifacts on Linux systems."""
    def _setup_browser_paths(self):
        """Set up Chrome-specific file paths."""
        chrome_profile_dir = Path(f"/home/{self.target_user}/.config/google-chrome/Default")
        self.history_db_path = chrome_profile_dir / "History"
        self.cookies_db_path = chrome_profile_dir / "Cookies"
    
    def extract_history_with_referrers(self):
        """Extract Chrome history with referrer URLs."""
        history_data = []
        try:
            conn = sqlite3.connect(self.temp_history_path)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            cursor = conn.cursor()
            query = """
            SELECT 
                urls.url,
                urls.title,
                visits.visit_time,
                urls.visit_count,
                (SELECT urls.url FROM visits AS v JOIN urls ON v.url = urls.id 
                 WHERE v.id = visits.from_visit) AS referrer_url
            FROM visits
            JOIN urls ON visits.url = urls.id
            ORDER BY visits.visit_time DESC
            """
            cursor.execute(query)
            rows = cursor.fetchall()
            for row in rows:
                # Convert Chrome timestamp (microseconds since Jan 1, 1601) to readable format
                chrome_epoch = datetime.datetime(1601, 1, 1)
                delta = datetime.timedelta(microseconds=row['visit_time'])
                visit_datetime = chrome_epoch + delta
                history_data.append({
                    'browser_name': self.browser_name,
                    'url': row['url'],
                    'title': row['title'],
                    'visit_time': visit_datetime.strftime('%Y-%m-%d %H:%M:%S'),
                    'visit_count': row['visit_count'],
                    'referrer_url': row['referrer_url'] if row['referrer_url'] else "Direct Navigation"
                })
            cursor.close()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"SQLite error extracting Chrome history: {e}")
        return history_data
    
    def extract_cookies(self):
        """Extract Chrome cookies."""
        cookie_data = []
        try:
            conn = sqlite3.connect(self.temp_cookies_path)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            cursor = conn.cursor()
            # Extract cookies
            cursor.execute("""
                SELECT creation_utc, host_key, path, name, value, encrypted_value, 
                       expires_utc, is_secure, is_httponly, last_access_utc, 
                       has_expires, is_persistent, priority, samesite, 
                       source_scheme, source_port 
                FROM cookies
            """)
            cookies = cursor.fetchall()
            for cookie in cookies:
                # Convert timestamps
                creation_time = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=cookie['creation_utc'])
                expiration_time = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=cookie['expires_utc'])
                last_access_time = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=cookie['last_access_utc'])
                cookie_data.append({
                    'browser_name': self.browser_name,
                    'creation_time': creation_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'host': cookie['host_key'],
                    'path': cookie['path'],
                    'name': cookie['name'],
                    'value': cookie['value'],
                    'expires': expiration_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'secure': bool(cookie['is_secure']),
                    'http_only': bool(cookie['is_httponly']),
                    'last_access': last_access_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'persistent': bool(cookie['is_persistent']),
                    'samesite': cookie['samesite'],
                    'source_scheme': cookie['source_scheme'],
                    'source_port': cookie['source_port']
                })
            cursor.close()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"SQLite error extracting Chrome cookies: {e}")
        return cookie_data

    def extract_downloads(self):
        """Extract Chrome download history."""
        downloads_data = []
        try:
            conn = sqlite3.connect(self.temp_history_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            # Chrome stores downloads in the downloads table
            query = """
            SELECT 
                downloads.id,
                downloads.target_path,
                downloads.tab_url AS source_url,
                downloads.start_time,
                downloads.end_time,
                downloads.total_bytes,
                downloads.state,
                downloads.interrupt_reason,
                downloads.mime_type,
                downloads_url_chains.url AS original_url
            FROM downloads
            LEFT JOIN downloads_url_chains 
                ON downloads.id = downloads_url_chains.id
            ORDER BY downloads.start_time DESC
            """
            cursor.execute(query)
            rows = cursor.fetchall()
            for row in rows:
                # Convert Chrome timestamps
                chrome_epoch = datetime.datetime(1601, 1, 1)
                start_time = None
                if row['start_time']:
                    delta = datetime.timedelta(microseconds=row['start_time'])
                    start_time = chrome_epoch + delta
                end_time = None
                if row['end_time']:
                    delta = datetime.timedelta(microseconds=row['end_time'])
                    end_time = chrome_epoch + delta
                # Map download state integer to string
                state_map = {
                    0: "In Progress",
                    1: "Complete",
                    2: "Cancelled",
                    3: "Interrupted",
                    4: "Interrupted"
                }
                state = state_map.get(row['state'], f"Unknown ({row['state']})")
                # Get filename from target path
                filename = os.path.basename(row['target_path']) if row['target_path'] else "Unknown"
                downloads_data.append({
                    'browser_name': self.browser_name,
                    'download_id': row['id'],
                    'filename': filename,
                    'target_path': row['target_path'],
                    'source_url': row['source_url'],
                    'original_url': row['original_url'],
                    'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S') if start_time else None,
                    'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S') if end_time else None,
                    'size_bytes': row['total_bytes'],
                    'state': state,
                    'interrupt_reason': row['interrupt_reason'],
                    'mime_type': row['mime_type']
                })
            cursor.close()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"SQLite error extracting Chrome downloads: {e}")
        return downloads_data

class Firefox(BrowserBase):
    """Class for extracting Firefox browser artifacts on Linux systems."""
    def __init__(self, target_user=None):
        # List to store multiple profile information
        self.profiles = []
        # Call the parent class constructor
        super().__init__(target_user)

    def _setup_browser_paths(self):
        """Set up Firefox-specific file paths with profiles.ini parsing."""
        firefox_profiles_dir = Path(f"/home/{self.target_user}/.mozilla/firefox")
        profiles_ini_path = firefox_profiles_dir / "profiles.ini"
        # Check if profiles.ini exists
        if not profiles_ini_path.exists():
            logger.warning(f"Firefox profiles.ini not found at {profiles_ini_path}")
            self.history_db_path = None
            self.cookies_db_path = None
            return
        try:
            # Read profiles.ini and find all profiles
            profiles_content = profiles_ini_path.read_text()
            profile_pattern = r'Path=(\S+)\n'
            profile_paths = re.findall(profile_pattern, profiles_content)
            logger.info(f"Found {len(profile_paths)} Firefox profiles in profiles.ini")
            # Process each profile path
            for profile_path in profile_paths:
                full_profile_path = firefox_profiles_dir / profile_path
                if not full_profile_path.exists():
                    continue
                # Check if this profile has the database files we need
                history_db = full_profile_path / "places.sqlite"
                cookies_db = full_profile_path / "cookies.sqlite"
                profile_info = {
                    'name': profile_path,
                    'path': full_profile_path,
                    'history_db': history_db if history_db.exists() else None,
                    'cookies_db': cookies_db if cookies_db.exists() else None,
                    'has_history': history_db.exists(),
                    'has_cookies': cookies_db.exists()
                }
                # Only add profiles that have at least one of the databases
                if profile_info['has_history'] or profile_info['has_cookies']:
                    self.profiles.append(profile_info)
                    logger.info(f"Added Firefox profile: {profile_path}")
            # Set default paths to the first valid profile if any exist
            if self.profiles:
                first_profile = self.profiles[0]
                self.history_db_path = first_profile['history_db']
                self.cookies_db_path = first_profile['cookies_db']
                logger.info(f"Set default Firefox profile to: {first_profile['name']}")
            else:
                logger.warning("No valid Firefox profiles found with database files")
                self.history_db_path = None
                self.cookies_db_path = None
        except Exception as e:
            logger.error(f"Error parsing Firefox profiles.ini: {e}")
            self.history_db_path = None
            self.cookies_db_path = None
    
    def is_installed(self):
        """Check if Firefox is installed by looking for valid profiles."""
        if not self.profiles:
            logger.warning("No Firefox profiles found")
            return False
        # Firefox is considered installed if at least one profile has usable databases
        for profile in self.profiles:
            if profile['has_history'] or profile['has_cookies']:
                logger.info(f"Firefox is installed with valid profile: {profile['name']}")
                return True
        logger.warning("No Firefox profiles with valid databases found")
        return False

    def extract_history_with_referrers(self):
        """Extract Firefox history with referrer URLs from the current profile."""
        history_data = []
        # Skip if no history database is set
        if not self.temp_history_path or not os.path.exists(self.temp_history_path):
            logger.warning("No Firefox history database available for extraction")
            return history_data
        try:
            conn = sqlite3.connect(self.temp_history_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            # Query to extract history with referrers
            query = """
            SELECT 
                p.url,
                p.title,
                h.visit_date,
                p.visit_count,
                (SELECT p2.url FROM moz_historyvisits h2 
                JOIN moz_places p2 ON h2.place_id = p2.id 
                WHERE h2.id = h.from_visit) AS referrer_url
            FROM moz_historyvisits h
            JOIN moz_places p ON h.place_id = p.id
            ORDER BY h.visit_date DESC
            """
            cursor.execute(query)
            rows = cursor.fetchall()
            for row in rows:
                # Firefox timestamps are in microseconds since Jan 1, 1970
                visit_datetime = datetime.datetime.fromtimestamp(row['visit_date'] / 1000000)
                history_data.append({
                    'browser_name': self.browser_name,
                    'url': row['url'],
                    'title': row['title'] or '',
                    'visit_time': visit_datetime.strftime('%Y-%m-%d %H:%M:%S'),
                    'visit_count': row['visit_count'],
                    'referrer_url': row['referrer_url'] if row['referrer_url'] else "Direct Navigation"
                })
            cursor.close()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"SQLite error extracting Firefox history: {e}")
        return history_data
    
    def extract_cookies(self):
        """Extract Firefox cookies from the current profile."""
        cookie_data = []
        # Skip if no cookies database is set
        if not self.temp_cookies_path or not os.path.exists(self.temp_cookies_path):
            logger.warning("No Firefox cookies database available for extraction")
            return cookie_data
        try:
            conn = sqlite3.connect(self.temp_cookies_path)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            cursor = conn.cursor()
            # Firefox cookie fields are slightly different from Chrome
            cursor.execute("""
                SELECT creationTime, host, path, name, value, 
                       expiry, isSecure, isHttpOnly, lastAccessed,
                       COALESCE(sameSite, 0) as sameSite, schemeMap
                FROM moz_cookies
            """)
            cookies = cursor.fetchall()
            for cookie in cookies:
                # Convert timestamps (Firefox uses microseconds since Jan 1, 1970)
                creation_datetime = datetime.datetime.fromtimestamp(cookie['creationTime'] / 1000000)
                # Firefox expiry is in seconds since Jan 1, 1970
                expiry_datetime = datetime.datetime.fromtimestamp(cookie['expiry'])
                last_access_datetime = datetime.datetime.fromtimestamp(cookie['lastAccessed'] / 1000000)
                # Map Firefox samesite values to strings (0=none, 1=lax, 2=strict)
                samesite_map = {0: "none", 1: "lax", 2: "strict"}
                samesite_str = samesite_map.get(cookie['sameSite'], str(cookie['sameSite']))
                cookie_data.append({
                    'browser_name': self.browser_name,
                    'creation_time': creation_datetime.strftime('%Y-%m-%d %H:%M:%S'),
                    'host': cookie['host'],
                    'path': cookie['path'],
                    'name': cookie['name'],
                    'value': cookie['value'],
                    'expires': expiry_datetime.strftime('%Y-%m-%d %H:%M:%S'),
                    'secure': bool(cookie['isSecure']),
                    'http_only': bool(cookie['isHttpOnly']),
                    'last_access': last_access_datetime.strftime('%Y-%m-%d %H:%M:%S'),
                    'persistent': cookie['expiry'] > 0,  # Firefox doesn't have a is_persistent field
                    'samesite': samesite_str,
                    'source_scheme': cookie['schemeMap'],
                    'source_port': ''  # Firefox doesn't store source_port
                })
            cursor.close()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"SQLite error extracting Firefox cookies: {e}")
        return cookie_data

    def extract_downloads(self):
        """Extract Firefox download history."""
        downloads_data = []
        try:
            conn = sqlite3.connect(self.temp_history_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            # Firefox stores downloads differently
            # In newer versions, you need to query moz_places and moz_annos
            query = """
            SELECT 
                p.id,
                p.url AS source_url,
                a.content AS target_path,
                p.title,
                p.last_visit_date,
                p.visit_count,
                a2.content AS filesize
            FROM moz_places p
            LEFT JOIN moz_annos a ON p.id = a.place_id AND a.anno_attribute_id = 
                (SELECT id FROM moz_anno_attributes WHERE name = 'downloads/destinationFileURI')
            LEFT JOIN moz_annos a2 ON p.id = a2.place_id AND a2.anno_attribute_id = 
                (SELECT id FROM moz_anno_attributes WHERE name = 'downloads/destFileSize')
            WHERE p.url LIKE 'file:%' 
               OR p.url LIKE 'about:downloads%'
               OR p.url LIKE 'place:transition=7%'
            """
            cursor.execute(query)
            rows = cursor.fetchall()
            for row in cursor.fetchall():
                # Convert Firefox timestamp (microseconds since Jan 1, 1970)
                visit_datetime = None
                if row['last_visit_date']:
                    visit_datetime = datetime.datetime.fromtimestamp(row['last_visit_date'] / 1000000)
                # Parse target path (which is a URI like file:///path/to/file)
                target_path = row['target_path']
                filename = "Unknown"
                if target_path and target_path.startswith('file:///'):
                    # Remove file:// prefix
                    clean_path = target_path.replace('file://', '')
                    filename = os.path.basename(clean_path)
                downloads_data.append({
                    'browser_name': self.browser_name,
                    'download_id': row['id'],
                    'filename': filename,
                    'target_path': target_path,
                    'source_url': row['source_url'],
                    'original_url': row['source_url'],  # Firefox doesn't track redirect chains
                    'start_time': visit_datetime.strftime('%Y-%m-%d %H:%M:%S') if visit_datetime else None,
                    'end_time': None,  # Firefox doesn't store end time separately
                    'size_bytes': row['filesize'] if row['filesize'] else None,
                    'state': 'Complete',  # Firefox doesn't store detailed state
                    'interrupt_reason': None,
                    'mime_type': None
                })
            # For newer versions of Firefox, also try the downloads table if available
            try:
                downloads_query = """
                SELECT 
                    id,
                    target_path,
                    source AS source_url,
                    name AS filename,
                    start_time,
                    end_time,
                    current_bytes,
                    total_bytes,
                    state
                FROM moz_downloads
                """
                cursor.execute(downloads_query)
                for row in cursor.fetchall():
                    # Convert timestamps
                    start_time = datetime.datetime.fromtimestamp(row['start_time'] / 1000000) if row['start_time'] else None
                    end_time = datetime.datetime.fromtimestamp(row['end_time'] / 1000000) if row['end_time'] else None
                    # Map state to string
                    state_map = {
                        1: "In Progress",
                        2: "Complete",
                        3: "Failed",
                        4: "Cancelled"
                    }
                    state = state_map.get(row['state'], f"Unknown ({row['state']})")
                    downloads_data.append({
                        'browser_name': self.browser_name,
                        'download_id': row['id'],
                        'filename': row['filename'],
                        'target_path': row['target_path'],
                        'source_url': row['source_url'],
                        'original_url': row['source_url'],
                        'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S') if start_time else None,
                        'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S') if end_time else None,
                        'size_bytes': row['total_bytes'],
                        'state': state,
                        'interrupt_reason': None,
                        'mime_type': None
                    })
            except sqlite3.OperationalError:
                # Table may not exist in this Firefox version
                pass
            cursor.close()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"SQLite error extracting Firefox downloads: {e}")
        return downloads_data

class Edge(BrowserBase):
    """Class for extracting Microsoft Edge browser artifacts on Linux systems."""
    def _setup_browser_paths(self):
        """Set up Edge-specific file paths."""
        # Edge on Linux uses a similar structure to Chrome
        edge_profile_dir = Path(f"/home/{self.target_user}/.config/microsoft-edge/Default")
        self.history_db_path = edge_profile_dir / "History"
        self.cookies_db_path = edge_profile_dir / "Cookies"
    
    def extract_history_with_referrers(self):
        """Extract Edge history with referrer URLs."""
        history_data = []
        try:
            conn = sqlite3.connect(self.temp_history_path)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            cursor = conn.cursor()
            # Edge uses the same schema as Chrome
            query = """
            SELECT 
                urls.url,
                urls.title,
                visits.visit_time,
                urls.visit_count,
                (SELECT urls.url FROM visits AS v JOIN urls ON v.url = urls.id 
                 WHERE v.id = visits.from_visit) AS referrer_url
            FROM visits
            JOIN urls ON visits.url = urls.id
            ORDER BY visits.visit_time DESC
            """
            cursor.execute(query)
            rows = cursor.fetchall()
            for row in rows:
                # Convert Chromium timestamp (microseconds since Jan 1, 1601) to readable format
                chrome_epoch = datetime.datetime(1601, 1, 1)
                delta = datetime.timedelta(microseconds=row['visit_time'])
                visit_datetime = chrome_epoch + delta
                history_data.append({
                    'browser_name': self.browser_name,
                    'url': row['url'],
                    'title': row['title'],
                    'visit_time': visit_datetime.strftime('%Y-%m-%d %H:%M:%S'),
                    'visit_count': row['visit_count'],
                    'referrer_url': row['referrer_url'] if row['referrer_url'] else "Direct Navigation"
                })
            cursor.close()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"SQLite error extracting Edge history: {e}")
        return history_data
    
    def extract_cookies(self):
        """Extract Edge cookies."""
        cookie_data = []
        try:
            conn = sqlite3.connect(self.temp_cookies_path)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            cursor = conn.cursor()
            # Edge uses the same schema as Chrome
            cursor.execute("""
                SELECT creation_utc, host_key, path, name, value, encrypted_value, 
                       expires_utc, is_secure, is_httponly, last_access_utc, 
                       has_expires, is_persistent, priority, samesite, 
                       source_scheme, source_port 
                FROM cookies
            """)
            cookies = cursor.fetchall()
            for cookie in cookies:
                # Convert timestamps
                creation_time = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=cookie['creation_utc'])
                expiration_time = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=cookie['expires_utc'])
                last_access_time = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=cookie['last_access_utc'])
                cookie_data.append({
                    'browser_name': self.browser_name,
                    'creation_time': creation_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'host': cookie['host_key'],
                    'path': cookie['path'],
                    'name': cookie['name'],
                    'value': cookie['value'],
                    'expires': expiration_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'secure': bool(cookie['is_secure']),
                    'http_only': bool(cookie['is_httponly']),
                    'last_access': last_access_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'persistent': bool(cookie['is_persistent']),
                    'samesite': cookie['samesite'],
                    'source_scheme': cookie['source_scheme'],
                    'source_port': cookie['source_port']
                })
            cursor.close()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"SQLite error extracting Edge cookies: {e}")
        return cookie_data

    def extract_downloads(self):
        """Extract Edge download history."""
        downloads_data = []
        try:
            conn = sqlite3.connect(self.temp_history_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            # Edge uses same schema as Chrome
            query = """
            SELECT 
                downloads.id,
                downloads.target_path,
                downloads.tab_url AS source_url,
                downloads.start_time,
                downloads.end_time,
                downloads.total_bytes,
                downloads.state,
                downloads.interrupt_reason,
                downloads.mime_type,
                downloads_url_chains.url AS original_url
            FROM downloads
            LEFT JOIN downloads_url_chains 
                ON downloads.id = downloads_url_chains.id
            ORDER BY downloads.start_time DESC
            """
            cursor.execute(query)
            rows = cursor.fetchall()
            for row in rows:
                # Convert Edge timestamps (same as Chrome)
                edge_epoch = datetime.datetime(1601, 1, 1)
                start_time = None
                if row['start_time']:
                    delta = datetime.timedelta(microseconds=row['start_time'])
                    start_time = edge_epoch + delta
                end_time = None
                if row['end_time']:
                    delta = datetime.timedelta(microseconds=row['end_time'])
                    end_time = edge_epoch + delta
                # Map download state
                state_map = {
                    0: "In Progress",
                    1: "Complete",
                    2: "Cancelled",
                    3: "Interrupted",
                    4: "Interrupted"
                }
                state = state_map.get(row['state'], f"Unknown ({row['state']})")
                # Get filename from target path
                filename = os.path.basename(row['target_path']) if row['target_path'] else "Unknown"
                downloads_data.append({
                    'browser_name': self.browser_name,
                    'download_id': row['id'],
                    'filename': filename,
                    'target_path': row['target_path'],
                    'source_url': row['source_url'],
                    'original_url': row['original_url'],
                    'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S') if start_time else None,
                    'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S') if end_time else None,
                    'size_bytes': row['total_bytes'],
                    'state': state,
                    'interrupt_reason': row['interrupt_reason'],
                    'mime_type': row['mime_type']
                })
            cursor.close()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"SQLite error extracting Edge downloads: {e}")
        return downloads_data

class BrowserExtractor:
    """Utility class to extract artifacts from multiple browsers in one operation."""
    
    def __init__(self, target_user=None):
        """
        Initialize the multi-browser extractor.
        Args:
            target_user (str, optional): Username to extract data from. Defaults to current user.
        """
        self.target_user = target_user
        self.available_browsers = {}
        # Initialize and check available browser extractors
        self._initialize_browsers()
    
    @staticmethod
    def get_system_users():
        """Get list of real users on the Linux system"""
        real_users = []
        try:
            etc_passwd = Path('/etc/passwd')
            if not etc_passwd.exists():
                logger.error("/etc/passwd not found")
                return real_users
            passwd_content = etc_passwd.read_text()
            # Parse each line properly instead of using regex
            for line in passwd_content.splitlines():
                if not line.strip():
                    continue 
                fields = line.split(':')
                if len(fields) >= 7:
                    username = fields[0]
                    uid = int(fields[2])
                    shell = fields[6]
                    # Check for real users
                    valid_shells = ['/bin/bash', '/bin/sh', '/bin/zsh', '/bin/fish']
                    if (uid >= 1000 or uid == 0) and shell in valid_shells:
                        real_users.append(username)
        except Exception as e:
            logger.error(f"Error parsing /etc/passwd: {e}")
        return real_users
    
    def extract_from_all_users(self):
        """Extract browser artifacts from all valid users on the system"""
        users = self.get_system_users()
        all_user_data = {}
        logger.info(f"Found {len(users)} valid users: {users}")
        for user in users:
            logger.info(f"Extracting browser data for user: {user}")
            # Create a new extractor instance for each user
            user_extractor = BrowserExtractor(target_user=user)
            # Extract data for this user
            user_data = user_extractor.extract_from_all_browsers()
            # Store results
            all_user_data[user] = user_data
        return all_user_data

    def _initialize_browsers(self):
        """Initialize all supported browser extractors and check availability."""
        # Chrome
        chrome = Chrome(self.target_user)
        if chrome.is_installed():
            self.available_browsers['chrome'] = chrome
        # Firefox
        firefox = Firefox(self.target_user)
        if firefox.is_installed():
            self.available_browsers['firefox'] = firefox
        # Edge
        edge = Edge(self.target_user)
        if edge.is_installed():
            self.available_browsers['edge'] = edge
        logger.info(f"Found {len(self.available_browsers)} installed browsers")
    
    def get_available_browsers(self):
        """
        Get list of available browsers.
        Returns:
            List[str]: List of browser names
        """
        return list(self.available_browsers.keys())
    
    def extract_from_browser(self, browser_name):
        """Extract artifacts from a specific browser."""
        browser_name = browser_name.lower()
        if browser_name not in self.available_browsers:
            logger.warning(f"Browser '{browser_name}' not available")
            return {'history': [], 'cookies': []}
        return self.available_browsers[browser_name].extract_all_artifacts()
    
    def extract_from_all_browsers(self):
        """
        Extract artifacts from all available browsers.
        Returns:
            Dict[str, Dict[str, List[Dict[str, Any]]]]: Nested dictionary with browser names as keys,
                                                     each containing 'history' and 'cookies' data
        """
        all_data = {}
        for browser_name, browser in self.available_browsers.items():
            logger.info(f"Extracting artifacts from {browser_name}...")
            browser_data = browser.extract_all_artifacts()
            all_data[browser_name] = browser_data
        return all_data
    
    def extract_all_history(self):
        """
        Extract history from all available browsers.
        Returns:
            Dict[str, List[Dict[str, Any]]]: Dictionary with browser names as keys and history data as values
        """
        history_data = {}
        for browser_name, browser in self.available_browsers.items():
            logger.info(f"Extracting history from {browser_name}...")
            browser_data = browser.extract_all_artifacts()
            history_data[browser_name] = browser_data['history']
        return history_data
    
    def extract_all_cookies(self):
        """
        Extract cookies from all available browsers.
        Returns:
            Dict[str, List[Dict[str, Any]]]: Dictionary with browser names as keys and cookie data as values
        """
        cookies_data = {}
        for browser_name, browser in self.available_browsers.items():
            logger.info(f"Extracting cookies from {browser_name}...")
            browser_data = browser.extract_all_artifacts()
            cookies_data[browser_name] = browser_data['cookies']
        return cookies_data
    
    def extract_single_browser(self, browser_name):
        """
        Extract artifacts from a single specified browser.
        Args:
            browser_name (str): Name of the browser to extract from
        Returns:
            Dict[str, List[Dict[str, Any]]]: Dictionary with 'history' and 'cookies' keys
        """
        browser_name = browser_name.lower()
        if browser_name not in self.available_browsers:
            logger.warning(f"Browser '{browser_name}' not available")
            return {'history': [], 'cookies': []}
        return self.available_browsers[browser_name].extract_all_artifacts()

    def extract_from_all_users(self, browser_name=None):
        """
        Extract browser artifacts from all valid users on the system.
        Args:
            browser_name (str, optional): Specific browser to extract from.
                                        If None, extract from all available browsers.                             
        Returns:
            Dict[str, Dict[str, Any]]: Dictionary with users as keys, each containing browser data
        """
        users = self.get_system_users()
        all_user_data = {}
        logger.info(f"Found {len(users)} valid users: {users}")
        for user in users:
            logger.info(f"Extracting browser data for user: {user}") 
            # Create a new extractor instance for each user
            user_extractor = BrowserExtractor(target_user=user)
            # Extract data for this user, from either a specific browser or all browsers
            if browser_name:
                user_data = {browser_name: user_extractor.extract_single_browser(browser_name)}
            else:
                user_data = user_extractor.extract_from_all_browsers()
            # Store results
            all_user_data[user] = user_data
        return all_user_data
