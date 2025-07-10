import os
import sqlite3
import shutil
import tempfile
from pathlib import Path
import datetime
import logging
import re
import sys
import winreg  # For Windows registry access
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
    """Abstract base class for extracting browser artifacts on Windows systems."""
    
    def __init__(self, target_user=None):
        """
        Initialize the browser artifact extractor.
        Args:
            target_user (str, optional): Username to extract data from. Defaults to current user.
        """
        self.target_user = target_user or os.getenv('USERNAME')
        self.browser_name = self.__class__.__name__.replace('Win', '').lower()
        # Get user profile paths
        self.users_folder = Path("C:/Users")
        self.user_profile = self.users_folder / self.target_user
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
    
    def _copy_with_robocopy(self, source_path, dest_path):
        """Copy a locked file using ROBOCOPY's backup mode (Windows only)."""
        import subprocess
        try:
            # Get directory and filename components
            source_dir = os.path.dirname(source_path)
            dest_dir = os.path.dirname(dest_path)
            filename = os.path.basename(source_path)
            # Run robocopy with backup mode
            logger.info(f"Using ROBOCOPY to copy {source_path}")
            result = subprocess.run(
                ['robocopy', source_dir, dest_dir, filename, '/B', '/R:1', '/W:1'],
                capture_output=True, text=True
            )
            # Robocopy returns non-zero even for success, check if file exists
            success = os.path.exists(dest_path)
            if success:
                logger.info(f"ROBOCOPY successful for {filename}")
            else:
                logger.error(f"ROBOCOPY failed: {result.stderr}")
            return success
        except Exception as e:
            logger.error(f"ROBOCOPY failed: {e}")
            return False
        
    def _setup_temp_files(self):
        """
        Create temporary copies of browser databases, handling locked files.
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
            # Copy history database - try direct copy first, then SQLite backup if locked
            try:
                shutil.copy2(self.history_db_path, self.temp_history_path)
                logger.info(f"Copied {self.browser_name} history database directly")
            except (PermissionError, OSError) as e:
                logger.warning(f"Direct copy of history database failed: {e}")
                try:
                    # Get absolute paths to ensure correct file access
                    abs_history_path = os.path.abspath(self.history_db_path)
                    logger.info(f"Trying SQLite backup with absolute path: {abs_history_path}")
                    # Try with explicit file path (not URI)
                    try:
                        # First try without URI syntax
                        src_conn = sqlite3.connect(abs_history_path)
                        dst_conn = sqlite3.connect(self.temp_history_path)
                        src_conn.backup(dst_conn)
                        src_conn.close()
                        dst_conn.close()
                        logger.info(f"Used standard SQLite connection for {self.browser_name} history database")
                    except sqlite3.OperationalError as e3:
                        logger.warning(f"Standard SQLite connection failed: {e3}")
                        # Then try with URI syntax
                        src_conn = sqlite3.connect(f"file:{abs_history_path}?mode=ro", uri=True)
                        dst_conn = sqlite3.connect(self.temp_history_path)
                        src_conn.backup(dst_conn)
                        src_conn.close()
                        dst_conn.close()
                        logger.info(f"Used SQLite URI mode for {self.browser_name} history database")
                except Exception as e2:
                    logger.error(f"SQLite backup of history database failed: {e2}")
                    # Continue anyway - we might still get cookies
            # Copy cookies database - try direct copy first, then SQLite backup if locked
            cookies_copied = False
            try:
                shutil.copy2(self.cookies_db_path, self.temp_cookies_path)
                logger.info(f"Copied {self.browser_name} cookies database directly")
                cookies_copied = True
            except (PermissionError, OSError) as e:
                logger.warning(f"Direct copy of cookies database failed: {e}")
                try:
                    # Get absolute paths to ensure correct file access
                    abs_cookies_path = os.path.abspath(self.cookies_db_path)
                    logger.info(f"Trying SQLite backup with absolute path: {abs_cookies_path}")
                    # Check if file is accessible at all
                    logger.info(f"Checking cookies file accessibility: exists={os.path.exists(abs_cookies_path)}, size={os.path.getsize(abs_cookies_path)}")
                    # Try multiple approaches
                    try:
                        # First try without URI syntax
                        src_conn = sqlite3.connect(abs_cookies_path)
                        dst_conn = sqlite3.connect(self.temp_cookies_path)
                        src_conn.backup(dst_conn)
                        src_conn.close()
                        dst_conn.close()
                        logger.info(f"Used standard SQLite connection for {self.browser_name} cookies database")
                        cookies_copied = True
                    except sqlite3.OperationalError as e3:
                        logger.warning(f"Standard SQLite connection failed: {e3}")
                        # Then try with URI syntax
                        src_conn = sqlite3.connect(f"file:{abs_cookies_path}?mode=ro", uri=True)
                        dst_conn = sqlite3.connect(self.temp_cookies_path)
                        src_conn.backup(dst_conn)
                        src_conn.close()
                        dst_conn.close()
                        logger.info(f"Used SQLite URI mode for {self.browser_name} cookies database")
                        cookies_copied = True
                except Exception as e2:
                    logger.error(f"SQLite backup of cookies database failed: {e2}")
                    # If SQLite backup failed for cookies on Windows, try ROBOCOPY
                    if not cookies_copied and sys.platform.startswith('win'):
                        logger.info("Attempting to copy cookies with ROBOCOPY...")
                        cookies_copied = self._copy_with_robocopy(abs_cookies_path, self.temp_cookies_path)
                        if cookies_copied:
                            logger.info(f"Successfully copied {self.browser_name} cookies database using ROBOCOPY")
            # If we got at least the history database, consider it a partial success
            if os.path.exists(self.temp_history_path):
                if not cookies_copied:
                    # Mark cookies as unavailable
                    self.temp_cookies_path = None
                    logger.warning(f"Continuing with only history database for {self.browser_name} (cookies unavailable)")
                return True
            else:
                logger.error(f"Failed to copy any databases for {self.browser_name}")
                return False
        except Exception as e:
            logger.error(f"Error setting up temporary files for {self.browser_name}: {e}")
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir, ignore_errors=True)
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
        if not history_exists:
            logger.warning(f"{self.browser_name}: History database not found or not accessible")
        if not cookies_exists:
            logger.warning(f"{self.browser_name}: Cookies database not found or not accessible")
        is_installed = history_exists and cookies_exists
        logger.info(f"{self.browser_name} installed status: {is_installed}")
        return is_installed

class Chrome(BrowserBase):
    """Class for extracting Chrome browser artifacts on Windows systems."""

    def _setup_browser_paths(self):
        """Set up Chrome-specific file paths."""
        local_app_data = self.user_profile / "AppData/Local/Google/Chrome/User Data/Default"
        # Check for the standard profile first
        if not local_app_data.exists():
            logger.warning(f"Chrome Default profile not found at {local_app_data}")
            # Try to look for other potential locations
            alternate_locations = [
                self.user_profile / "AppData/Local/Google/Chrome/User Data",
                self.user_profile / "Local Settings/Application Data/Google/Chrome/User Data"  # For older Windows
            ]
            for location in alternate_locations:
                if location.exists():
                    profile_dirs = [d for d in location.iterdir() if d.is_dir() and (d.name == "Default" or d.name.startswith("Profile"))]
                    if profile_dirs:
                        local_app_data = profile_dirs[0]  # Use the first profile found
                        logger.info(f"Using Chrome profile at {local_app_data}")
                        break
        self.history_db_path = local_app_data / "History"
        self.cookies_db_path = local_app_data / "Network\Cookies"
    
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
    """Class for extracting Firefox browser artifacts on Windows systems."""
    
    def __init__(self, target_user=None):
        # List to store multiple profile information
        self.profiles = []
        # Call the parent class constructor
        super().__init__(target_user)
    
    def _setup_browser_paths(self):
        """Set up Firefox-specific file paths."""
        # Firefox profile location on Windows
        firefox_profiles_dir = self.user_profile / "AppData/Roaming/Mozilla/Firefox/Profiles"
        profiles_ini_path = self.user_profile / "AppData/Roaming/Mozilla/Firefox/profiles.ini"
        # Check if profiles.ini exists
        if not profiles_ini_path.exists():
            # Try alternate location for older Windows
            firefox_profiles_dir = self.user_profile / "Application Data/Mozilla/Firefox/Profiles"
            profiles_ini_path = self.user_profile / "Application Data/Mozilla/Firefox/profiles.ini"
            if not profiles_ini_path.exists():
                logger.warning(f"Firefox profiles.ini not found for user {self.target_user}")
                self.history_db_path = None
                self.cookies_db_path = None
                return
        try:
            # Read profiles.ini and find all profiles
            profiles_content = profiles_ini_path.read_text()
            profile_pattern = r'Path=(\S+)'
            profile_paths = re.findall(profile_pattern, profiles_content)
            logger.info(f"Found {len(profile_paths)} Firefox profiles in profiles.ini")
            # Process each profile path
            for profile_path in profile_paths:
                full_profile_path = firefox_profiles_dir / profile_path
                if not full_profile_path.exists():
                    # Try with relative path
                    full_profile_path = self.user_profile / "AppData/Roaming/Mozilla/Firefox" / profile_path
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
        """Extract Firefox history with referrer URLs."""
        history_data = []
        # Skip if no history database is set
        if not self.temp_history_path or not os.path.exists(self.temp_history_path):
            logger.warning("No Firefox history database available for extraction")
            return history_data
        try:
            conn = sqlite3.connect(self.temp_history_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            # Firefox stores history in the moz_places table and visits in moz_historyvisits
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
                # Convert to readable format
                visit_datetime = datetime.datetime.fromtimestamp(row['visit_date'] / 1000000)
                history_data.append({
                    'browser_name': self.browser_name,
                    'url': row['url'],
                    'title': row['title'] or '',  # Handle None titles
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
        """Extract Firefox cookies."""
        cookie_data = []
        # Skip if no cookies database is set
        if not self.temp_cookies_path or not os.path.exists(self.temp_cookies_path):
            logger.warning("No Firefox cookies database available for extraction")
            return cookie_data
        try:
            conn = sqlite3.connect(self.temp_cookies_path)
            conn.row_factory = sqlite3.Row
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
                    # Remove file:// prefix and convert to Windows path
                    clean_path = target_path.replace('file:///', '')
                    # If path starts with a drive letter, it's already a Windows path
                    # Otherwise, it might need conversion
                    if not re.match(r'^[a-zA-Z]:', clean_path):
                        clean_path = clean_path.replace('/', '\\')
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
    """Class for extracting Microsoft Edge browser artifacts on Windows systems."""
    
    def _setup_browser_paths(self):
        """Set up Edge-specific file paths."""
        # For Chromium-based Edge (new version)
        edge_profile_dir = self.user_profile / "AppData/Local/Microsoft/Edge/User Data/Default"
        # Check if the profile exists
        if not edge_profile_dir.exists():
            # Try to look for other potential locations or profiles
            alternate_locations = [
                self.user_profile / "AppData/Local/Microsoft/Edge/User Data",
                # Legacy Edge (EdgeHTML) had a different location
                self.user_profile / "AppData/Local/Packages/Microsoft.MicrosoftEdge_8wekyb3d8bbwe/AC/MicrosoftEdge/User/Default",
                # For older Windows versions
                self.user_profile / "Local Settings/Application Data/Microsoft/Edge/User Data"
            ]
            for location in alternate_locations:
                if location.exists():
                    # If we found the User Data folder, look for profile directories
                    if location.name == "User Data":
                        profile_dirs = [d for d in location.iterdir() if d.is_dir() and (d.name == "Default" or d.name.startswith("Profile"))]
                        if profile_dirs:
                            edge_profile_dir = profile_dirs[0]  # Use first profile
                            logger.info(f"Using Edge profile at {edge_profile_dir}")
                            break
                    else:
                        edge_profile_dir = location
                        logger.info(f"Using Edge profile at {edge_profile_dir}")
                        break
        # Set paths for Chromium-based Edge
        self.history_db_path = edge_profile_dir / "History"
        self.cookies_db_path = edge_profile_dir / r"Network\Cookies"
        # For Legacy Edge, the databases might be in a different format
        # We focus on the Chromium-based Edge which is more common now
    
    def extract_history_with_referrers(self):
        """Extract Edge history with referrer URLs."""
        history_data = []
        try:
            conn = sqlite3.connect(self.temp_history_path)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            cursor = conn.cursor()
            # Edge uses same schema as Chrome
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
                # Convert Edge timestamps (same as Chrome)
                edge_epoch = datetime.datetime(1601, 1, 1)
                delta = datetime.timedelta(microseconds=row['visit_time'])
                visit_datetime = edge_epoch + delta
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
            # Skip if no cookies database is set or doesn't exist
        if not self.temp_cookies_path or not os.path.exists(self.temp_cookies_path):
            logger.warning(f"No {self.browser_name} cookies database available for extraction")
            return cookie_data
        try:
            conn = sqlite3.connect(self.temp_cookies_path)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            cursor = conn.cursor()
            # Edge uses same schema as Chrome
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

def get_system_users():
    """Get list of real users on the Windows system"""
    real_users = []
    try:
        # Windows user profiles are in C:\Users
        users_folder = Path("C:/Users")
        # Common system accounts to exclude
        system_accounts = {'Default', 'Public', 'Default User', 'All Users', 'Administrator', 'DefaultAccount', 'Guest'}
        for user_dir in users_folder.iterdir():
            if user_dir.is_dir() and user_dir.name not in system_accounts:
                # Check if this looks like a real user profile
                ntuser_dat = user_dir / "NTUSER.DAT"
                if ntuser_dat.exists():
                    real_users.append(user_dir.name)
        logger.info(f"Found {len(real_users)} Windows user profiles")
    except Exception as e:
        logger.error(f"Error getting Windows users: {e}")
    return real_users

class BrowserExtractor:
    """Utility class to extract artifacts from multiple browsers on Windows."""
    
    def __init__(self, target_user=None):
        """
        Initialize the multi-browser extractor.
        Args:
            target_user (str, optional): Username to extract data from. Defaults to current user.
        """
        self.target_user = target_user or os.getenv('USERNAME')
        self.available_browsers = {}
        # Initialize and check available browser extractors
        self._initialize_browsers()
    
    @staticmethod
    def get_system_users():
        """Get list of real users on the Windows system"""
        return get_system_users()
    
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
    
    def extract_single_browser(self, browser_name):
        """
        Extract artifacts from a single specified browser.
        Args:
            browser_name (str): Name of the browser to extract from
        Returns:
            Dict[str, List[Dict[str, Any]]]: Dictionary with 'history', 'cookies', and 'downloads' keys
        """
        browser_name = browser_name.lower()
        if browser_name not in self.available_browsers:
            logger.warning(f"Browser '{browser_name}' not available")
            return {'history': [], 'cookies': [], 'downloads': []}
        return self.available_browsers[browser_name].extract_all_artifacts()
    
    def extract_from_all_browsers(self):
        """
        Extract artifacts from all available browsers.
        Returns:
            Dict[str, Dict[str, List[Dict[str, Any]]]]: Nested dictionary with browser names as keys,
                                                     each containing 'history', 'cookies', and 'downloads' data
        """
        all_data = {}
        for browser_name, browser in self.available_browsers.items():
            logger.info(f"Extracting artifacts from {browser_name}...")
            browser_data = browser.extract_all_artifacts()
            all_data[browser_name] = browser_data
        return all_data
    
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
