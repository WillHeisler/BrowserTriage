# ============================================================================
# windows_remote.py
# ============================================================================

"""
Windows remote execution module for browsertriage.
Enables browser artifact extraction from remote Windows systems without Python dependency.
Enhanced with robust Firefox profile detection and extraction.
"""

import os
import sys
import tempfile
import subprocess
import shutil
import sqlite3
import time
import datetime
import logging
import re

# Configure logging
logger = logging.getLogger(__name__)

class WindowsRemoteExecutor:
    """Handles remote browser artifact extraction on Windows systems."""
    
    def __init__(self, method='winrm'):
        """
        Initialize the Windows remote executor.
        Args:
            method (str): Remote execution method ('winrm', 'wmi', 'auto', 'ssh', 'psexec')
        """
        self.method = method.lower()
        valid_methods = ['winrm', 'wmi', 'auto', 'ssh', 'psexec']
        if self.method not in valid_methods:
            logger.warning(f"Unknown method '{method}', defaulting to winrm")
            self.method = 'winrm'
        logger.info(f"Windows remote executor initialized with method: {self.method}")

    def extract(self, hostname, username, password, target_user='all', browser='all'):
        """
        Extract browser artifacts from a remote Windows system without Python dependency.
        Args:
            hostname: Remote host IP address or hostname
            username: Windows username (format: domain\\user or .\\user)
            password: Windows password
            target_user: Target user to extract browser data for (or 'all')
            browser: Browser to extract (or 'all')
        Returns:
            Dictionary containing extracted browser artifacts
        """
        try:
            logger.info(f"Starting remote extraction from {hostname} as {username} using {self.method.upper()}")
            temp_dir = tempfile.mkdtemp()
            remote_dir = f"C:\\Windows\\Temp\\browsertriage_{int(time.time())}"
            logger.debug(f"Local temp directory: {temp_dir}")
            logger.debug(f"Remote temp directory: {remote_dir}")
            cmd = f"mkdir {remote_dir}"
            self._run_remote_command(hostname, username, password, cmd)
            if target_user.lower() == 'all':
                cmd = "dir C:\\Users /B /AD"
                result = self._run_remote_command(hostname, username, password, cmd, get_output=True)
                if result:
                    all_users = [user.strip() for user in result.split('\n') if user.strip()]
                    users = [u for u in all_users if u.lower() not in ['public', 'default', 'defaultuser0', 'administrator']]
                    logger.info(f"Found {len(users)} users on {hostname}: {', '.join(users)}")
                else:
                    logger.warning("No users found, using current user")
                    users = [username.split('\\')[-1]]
            else:
                users = [target_user]
                logger.info(f"Using specified user: {target_user}")
            all_data = {}
            for user in users:
                user_data = {}
                logger.info(f"Processing user: {user}")
                browsers_to_extract = []
                if browser.lower() == 'all':
                    chrome_path = f"C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"
                    edge_path = f"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History"
                    firefox_base = f"C:\\Users\\{user}\\AppData\\Roaming\\Mozilla\\Firefox"
                    cmd = f"if exist \"{chrome_path}\" echo exists"
                    result = self._run_remote_command(hostname, username, password, cmd, get_output=True)
                    if "exists" in result:
                        browsers_to_extract.append('chrome')
                        logger.info(f"Chrome detected for user {user}")
                    cmd = f"if exist \"{edge_path}\" echo exists"
                    result = self._run_remote_command(hostname, username, password, cmd, get_output=True)
                    if "exists" in result:
                        browsers_to_extract.append('edge')
                        logger.info(f"Edge detected for user {user}")
                    firefox_detected = False
                    cmd = f"if exist \"{firefox_base}\\profiles.ini\" echo exists"
                    result = self._run_remote_command(hostname, username, password, cmd, get_output=True)
                    if "exists" in result:
                        firefox_detected = True
                        logger.info(f"Firefox detected for user {user} (via profiles.ini)")
                    if not firefox_detected:
                        cmd = f"if exist \"{firefox_base}\\Profiles\" echo exists"
                        result = self._run_remote_command(hostname, username, password, cmd, get_output=True)
                        if "exists" in result:
                            firefox_detected = True
                            logger.info(f"Firefox detected for user {user} (via Profiles directory)")
                    if not firefox_detected:
                        cmd = f"dir \"{firefox_base}\" /B 2>nul | findstr \".default\""
                        result = self._run_remote_command(hostname, username, password, cmd, get_output=True)
                        if result and result.strip():
                            firefox_detected = True
                            logger.info(f"Firefox detected for user {user} (via .default profile: {result.strip()})")
                    if not firefox_detected:
                        cmd = f"dir \"{firefox_base}\" /B /AD 2>nul"
                        result = self._run_remote_command(hostname, username, password, cmd, get_output=True)
                        if result and result.strip():
                            profile_dirs = [d.strip() for d in result.split('\n') if d.strip()]
                            for profile_dir in profile_dirs:
                                if profile_dir.lower() in ['profiles', 'crash reports', 'pending pings']:
                                    continue
                                cmd = f"if exist \"{firefox_base}\\{profile_dir}\\places.sqlite\" echo exists"
                                places_result = self._run_remote_command(hostname, username, password, cmd, get_output=True)
                                if "exists" in places_result:
                                    firefox_detected = True
                                    logger.info(f"Firefox detected for user {user} (via profile {profile_dir} with places.sqlite)")
                                    break
                    if firefox_detected:
                        browsers_to_extract.append('firefox')
                        logger.info(f"Firefox confirmed for extraction for user {user}")
                else:
                    browsers_to_extract = [browser.lower()]
                    logger.info(f"Using specified browser: {browser}")
                for browser_name in browsers_to_extract:
                    if browser_name == 'chrome':
                        user_data[browser_name] = self.extract_chrome(hostname, username, password, user, remote_dir, temp_dir)
                    elif browser_name == 'edge':
                        user_data[browser_name] = self.extract_edge(hostname, username, password, user, remote_dir, temp_dir)
                    elif browser_name == 'firefox':
                        user_data[browser_name] = self.extract_firefox(hostname, username, password, user, remote_dir, temp_dir)
                if user_data:
                    all_data[user] = user_data
            cmd = f"rmdir /s /q {remote_dir}"
            self._run_remote_command(hostname, username, password, cmd)
            logger.debug(f"Cleaned up remote directory: {remote_dir}")
            shutil.rmtree(temp_dir)
            logger.debug(f"Cleaned up local directory: {temp_dir}")
            return all_data
        except Exception as e:
            logger.error(f"Error during remote Windows extraction: {e}")
            return None

    def extract_chrome(self, hostname, username, password, target_user, remote_dir, temp_dir):
        """
        Extract Chrome browser artifacts from a remote Windows system.
        Args:
            hostname: Remote host to connect to
            username: Windows username
            password: Windows password
            target_user: User to extract data for
            remote_dir: Remote directory for temporary files
            temp_dir: Local directory for temporary files
        Returns:
            Dictionary with history, cookies, and downloads data
        """
        try:
            logger.info(f"Extracting Chrome data for user {target_user}")
            profile_dir = f"C:\\Users\\{target_user}\\AppData\\Local\\Google\\Chrome\\User Data\\Default"
            remote_history = f"{remote_dir}\\chrome_history.db"
            remote_cookies = f"{remote_dir}\\chrome_cookies.db"
            local_history = os.path.join(temp_dir, "chrome_history.db")
            local_cookies = os.path.join(temp_dir, "chrome_cookies.db")
            cmd = f"robocopy \"{profile_dir}\" \"{remote_dir}\" History /B /R:1 /W:1 >nul 2>&1"
            self._run_remote_command(hostname, username, password, cmd)
            cmd = f"if exist \"{remote_dir}\\History\" ren \"{remote_dir}\\History\" chrome_history.db >nul 2>&1"
            self._run_remote_command(hostname, username, password, cmd)
            cmd = f"robocopy \"{profile_dir}\" \"{remote_dir}\" Cookies /B /R:1 /W:1 >nul 2>&1"
            self._run_remote_command(hostname, username, password, cmd)
            cmd = f"if exist \"{remote_dir}\\Cookies\" ren \"{remote_dir}\\Cookies\" chrome_cookies.db >nul 2>&1"
            self._run_remote_command(hostname, username, password, cmd)
            history_copied = self._copy_file_from_remote(hostname, username, password, remote_history, local_history)
            cookies_copied = self._copy_file_from_remote(hostname, username, password, remote_cookies, local_cookies)
            result = {'history': [], 'cookies': [], 'downloads': []}
            if history_copied and os.path.exists(local_history):
                logger.debug(f"Processing Chrome history for {target_user}")
                try:
                    conn = sqlite3.connect(local_history)
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    cursor.execute("""
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
                    """)
                    for row in cursor.fetchall():
                        timestamp = row['visit_time']
                        if timestamp:
                            chrome_epoch = datetime.datetime(1601, 1, 1)
                            delta = datetime.timedelta(microseconds=timestamp)
                            visit_time = (chrome_epoch + delta).strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            visit_time = None
                        result['history'].append({
                            'browser_name': 'chrome',
                            'url': row['url'],
                            'title': row['title'],
                            'visit_time': visit_time,
                            'visit_count': row['visit_count'],
                            'referrer_url': row['referrer_url'] if row['referrer_url'] else "Direct Navigation"
                        })
                    cursor.execute("""
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
                    """)
                    for row in cursor.fetchall():
                        chrome_epoch = datetime.datetime(1601, 1, 1)
                        start_time = None
                        if row['start_time']:
                            delta = datetime.timedelta(microseconds=row['start_time'])
                            start_time = (chrome_epoch + delta).strftime('%Y-%m-%d %H:%M:%S')
                        end_time = None
                        if row['end_time']:
                            delta = datetime.timedelta(microseconds=row['end_time'])
                            end_time = (chrome_epoch + delta).strftime('%Y-%m-%d %H:%M:%S')
                        state_map = {
                            0: "In Progress",
                            1: "Complete",
                            2: "Cancelled",
                            3: "Interrupted",
                            4: "Interrupted"
                        }
                        state = state_map.get(row['state'], f"Unknown ({row['state']})")
                        filename = os.path.basename(row['target_path']) if row['target_path'] else "Unknown"
                        result['downloads'].append({
                            'browser_name': 'chrome',
                            'download_id': row['id'],
                            'filename': filename,
                            'target_path': row['target_path'],
                            'source_url': row['source_url'],
                            'original_url': row['original_url'],
                            'start_time': start_time,
                            'end_time': end_time,
                            'size_bytes': row['total_bytes'],
                            'state': state,
                            'interrupt_reason': row['interrupt_reason'],
                            'mime_type': row['mime_type']
                        })
                    cursor.close()
                    conn.close()
                    logger.debug(f"Extracted {len(result['history'])} history entries and {len(result['downloads'])} downloads")
                except Exception as e:
                    logger.debug(f"Error processing Chrome history: {e}")
            if cookies_copied and os.path.exists(local_cookies):
                logger.debug(f"Processing Chrome cookies for {target_user}")
                try:
                    conn = sqlite3.connect(local_cookies)
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT creation_utc, host_key, path, name, value, 
                            expires_utc, is_secure, is_httponly, last_access_utc, 
                            has_expires, is_persistent, priority, samesite, 
                            source_scheme, source_port 
                        FROM cookies
                    """)
                    for cookie in cursor.fetchall():
                        chrome_epoch = datetime.datetime(1601, 1, 1)
                        creation_time = chrome_epoch + datetime.timedelta(microseconds=cookie['creation_utc'])
                        creation_time = creation_time.strftime('%Y-%m-%d %H:%M:%S')
                        expiration_time = chrome_epoch + datetime.timedelta(microseconds=cookie['expires_utc'])
                        expiration_time = expiration_time.strftime('%Y-%m-%d %H:%M:%S')
                        last_access_time = chrome_epoch + datetime.timedelta(microseconds=cookie['last_access_utc'])
                        last_access_time = last_access_time.strftime('%Y-%m-%d %H:%M:%S')
                        result['cookies'].append({
                            'browser_name': 'chrome',
                            'creation_time': creation_time,
                            'host': cookie['host_key'],
                            'path': cookie['path'],
                            'name': cookie['name'],
                            'value': cookie['value'],
                            'expires': expiration_time,
                            'secure': bool(cookie['is_secure']),
                            'http_only': bool(cookie['is_httponly']),
                            'last_access': last_access_time,
                            'persistent': bool(cookie['is_persistent']),
                            'samesite': cookie['samesite'],
                            'source_scheme': cookie['source_scheme'],
                            'source_port': cookie['source_port']
                        })
                    cursor.close()
                    conn.close()
                    logger.debug(f"Extracted {len(result['cookies'])} cookies")
                except Exception as e:
                    logger.debug(f"Error processing Chrome cookies: {e}")
            return result
        except Exception as e:
            logger.error(f"Error extracting Chrome data: {e}")
            return {'history': [], 'cookies': [], 'downloads': []}

    def extract_edge(self, hostname, username, password, target_user, remote_dir, temp_dir):
        """Extract Edge browser artifacts from a remote Windows system."""
        try:
            logger.info(f"Extracting Edge data for user {target_user}")
            profile_dir = f"C:\\Users\\{target_user}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default"
            remote_history = f"{remote_dir}\\edge_history.db"
            remote_cookies = f"{remote_dir}\\edge_cookies.db"
            local_history = os.path.join(temp_dir, "edge_history.db")
            local_cookies = os.path.join(temp_dir, "edge_cookies.db")
            cmd = "taskkill /F /IM msedge.exe /T >nul 2>&1"
            self._run_remote_command(hostname, username, password, cmd)
            cmd = f"robocopy \"{profile_dir}\" \"{remote_dir}\" History /B /R:3 /W:2 >nul 2>&1"
            self._run_remote_command(hostname, username, password, cmd)
            cmd = f"if not exist \"{remote_dir}\\History\" copy \"{profile_dir}\\History\" \"{remote_dir}\\edge_history.db\" /Y >nul 2>&1"
            self._run_remote_command(hostname, username, password, cmd)
            cmd = f"if exist \"{remote_dir}\\History\" ren \"{remote_dir}\\History\" edge_history.db >nul 2>&1"
            self._run_remote_command(hostname, username, password, cmd)
            cmd = f"robocopy \"{profile_dir}\" \"{remote_dir}\" Cookies /B /R:3 /W:2 >nul 2>&1"
            self._run_remote_command(hostname, username, password, cmd)
            cmd = f"if not exist \"{remote_dir}\\Cookies\" copy \"{profile_dir}\\Cookies\" \"{remote_dir}\\edge_cookies.db\" /Y >nul 2>&1"
            self._run_remote_command(hostname, username, password, cmd)
            cmd = f"if exist \"{remote_dir}\\Cookies\" ren \"{remote_dir}\\Cookies\" edge_cookies.db >nul 2>&1"
            self._run_remote_command(hostname, username, password, cmd)
            history_copied = self._copy_file_from_remote(hostname, username, password, remote_history, local_history)
            cookies_copied = self._copy_file_from_remote(hostname, username, password, remote_cookies, local_cookies)
            result = {'history': [], 'cookies': [], 'downloads': []}
            if history_copied and os.path.exists(local_history):
                logger.debug(f"Processing Edge history for {target_user}")
                try:
                    conn = sqlite3.connect(local_history)
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    cursor.execute("""
                    SELECT 
                        urls.url,
                        urls.title,
                        visits.visit_time,
                        urls.visit_count,
                        (SELECT urls.url FROM visits AS v JOIN urls ON v.url = urls.id 
                        WHERE v.id = visits.from_visit) AS referrer_url
                    FROM visits
                    JOIN urls ON visits.url = urls.id
                    WHERE urls.url NOT LIKE 'edge://%'
                    ORDER BY visits.visit_time DESC
                    """)
                    for row in cursor.fetchall():
                        timestamp = row['visit_time']
                        if timestamp:
                            chrome_epoch = datetime.datetime(1601, 1, 1)
                            delta = datetime.timedelta(microseconds=timestamp)
                            visit_time = (chrome_epoch + delta).strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            visit_time = None
                        result['history'].append({
                            'browser_name': 'edge',
                            'url': row['url'],
                            'title': row['title'],
                            'visit_time': visit_time,
                            'visit_count': row['visit_count'],
                            'referrer_url': row['referrer_url'] if row['referrer_url'] else "Direct Navigation"
                        })
                    cursor.execute("""
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
                    """)
                    for row in cursor.fetchall():
                        chrome_epoch = datetime.datetime(1601, 1, 1)
                        start_time = None
                        if row['start_time']:
                            delta = datetime.timedelta(microseconds=row['start_time'])
                            start_time = (chrome_epoch + delta).strftime('%Y-%m-%d %H:%M:%S')
                        end_time = None
                        if row['end_time']:
                            delta = datetime.timedelta(microseconds=row['end_time'])
                            end_time = (chrome_epoch + delta).strftime('%Y-%m-%d %H:%M:%S')
                        state_map = {
                            0: "In Progress",
                            1: "Complete",
                            2: "Cancelled",
                            3: "Interrupted",
                            4: "Interrupted"
                        }
                        state = state_map.get(row['state'], f"Unknown ({row['state']})")
                        filename = os.path.basename(row['target_path']) if row['target_path'] else "Unknown"
                        result['downloads'].append({
                            'browser_name': 'edge',
                            'download_id': row['id'],
                            'filename': filename,
                            'target_path': row['target_path'],
                            'source_url': row['source_url'],
                            'original_url': row['original_url'],
                            'start_time': start_time,
                            'end_time': end_time,
                            'size_bytes': row['total_bytes'],
                            'state': state,
                            'interrupt_reason': row['interrupt_reason'],
                            'mime_type': row['mime_type']
                        })
                    cursor.close()
                    conn.close()
                    logger.debug(f"Extracted {len(result['history'])} Edge history entries and {len(result['downloads'])} downloads")
                except Exception as e:
                    logger.debug(f"Error processing Edge history: {e}")
            if cookies_copied and os.path.exists(local_cookies):
                logger.debug(f"Processing Edge cookies for {target_user}")
                try:
                    conn = sqlite3.connect(local_cookies)
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT creation_utc, host_key, path, name, value, 
                            expires_utc, is_secure, is_httponly, last_access_utc, 
                            has_expires, is_persistent, priority, samesite, 
                            source_scheme, source_port 
                        FROM cookies
                    """)
                    for cookie in cursor.fetchall():
                        chrome_epoch = datetime.datetime(1601, 1, 1)
                        creation_time = chrome_epoch + datetime.timedelta(microseconds=cookie['creation_utc'])
                        creation_time = creation_time.strftime('%Y-%m-%d %H:%M:%S')
                        expiration_time = chrome_epoch + datetime.timedelta(microseconds=cookie['expires_utc'])
                        expiration_time = expiration_time.strftime('%Y-%m-%d %H:%M:%S')
                        last_access_time = chrome_epoch + datetime.timedelta(microseconds=cookie['last_access_utc'])
                        last_access_time = last_access_time.strftime('%Y-%m-%d %H:%M:%S')
                        result['cookies'].append({
                            'browser_name': 'edge',
                            'creation_time': creation_time,
                            'host': cookie['host_key'],
                            'path': cookie['path'],
                            'name': cookie['name'],
                            'value': cookie['value'],
                            'expires': expiration_time,
                            'secure': bool(cookie['is_secure']),
                            'http_only': bool(cookie['is_httponly']),
                            'last_access': last_access_time,
                            'persistent': bool(cookie['is_persistent']),
                            'samesite': cookie['samesite'],
                            'source_scheme': cookie['source_scheme'],
                            'source_port': cookie['source_port']
                        })
                    cursor.close()
                    conn.close()
                    logger.debug(f"Extracted {len(result['cookies'])} Edge cookies")
                except Exception as e:
                    logger.debug(f"Error processing Edge cookies: {e}")
            return result
        except Exception as e:
            logger.error(f"Error extracting Edge data: {e}")
            return {'history': [], 'cookies': [], 'downloads': []}

    def extract_firefox(self, hostname, username, password, target_user, remote_dir, temp_dir):
        """Extract Firefox browser artifacts from a remote Windows system with enhanced profile detection."""
        try:
            logger.info(f"Extracting Firefox data for user {target_user}")
            result = {'history': [], 'cookies': [], 'downloads': []}
            firefox_base = f"C:\\Users\\{target_user}\\AppData\\Roaming\\Mozilla\\Firefox"
            profiles_found = []
            cmd = f"if exist \"{firefox_base}\\profiles.ini\" type \"{firefox_base}\\profiles.ini\""
            profiles_ini_content = self._run_remote_command(hostname, username, password, cmd, get_output=True)
            if profiles_ini_content and "Path=" in profiles_ini_content:
                logger.debug("Found profiles.ini, parsing profile paths")
                profile_paths = re.findall(r'Path=([^\r\n]+)', profiles_ini_content)
                for path in profile_paths:
                    path = path.strip()
                    if path:
                        if not path.startswith('C:'):
                            full_path = f"{firefox_base}\\{path}"
                        else:
                            full_path = path
                        profiles_found.append(full_path)
                        logger.debug(f"Found profile from profiles.ini: {full_path}")
            if not profiles_found:
                cmd = f"if exist \"{firefox_base}\\Profiles\" dir \"{firefox_base}\\Profiles\" /B /AD 2>nul"
                profiles_dir_content = self._run_remote_command(hostname, username, password, cmd, get_output=True)
                if profiles_dir_content and profiles_dir_content.strip():
                    logger.debug("Found Profiles directory, scanning for profiles")
                    profile_dirs = [d.strip() for d in profiles_dir_content.split('\n') if d.strip()]
                    for profile_dir in profile_dirs:
                        full_path = f"{firefox_base}\\Profiles\\{profile_dir}"
                        profiles_found.append(full_path)
                        logger.debug(f"Found profile in Profiles directory: {full_path}")
            if not profiles_found:
                cmd = f"dir \"{firefox_base}\" /B /AD 2>nul"
                base_dir_content = self._run_remote_command(hostname, username, password, cmd, get_output=True)
                if base_dir_content and base_dir_content.strip():
                    logger.debug("Scanning Firefox base directory for profiles")
                    dirs = [d.strip() for d in base_dir_content.split('\n') if d.strip()]
                    for dir_name in dirs:
                        if dir_name.lower() in ['profiles', 'crash reports', 'pending pings', 'extensions', 'updates']:
                            continue
                        full_path = f"{firefox_base}\\{dir_name}"
                        cmd = f"if exist \"{full_path}\\places.sqlite\" echo exists"
                        places_check = self._run_remote_command(hostname, username, password, cmd, get_output=True)
                        if "exists" in places_check:
                            profiles_found.append(full_path)
                            logger.debug(f"Found profile in base directory: {full_path}")
            if not profiles_found:
                logger.debug(f"No Firefox profiles found for user {target_user}")
                return result
            logger.info(f"Found {len(profiles_found)} Firefox profile(s) for user {target_user}")
            for profile_idx, profile_path in enumerate(profiles_found):
                logger.debug(f"Processing Firefox profile {profile_idx + 1}: {profile_path}")
                remote_history = f"{remote_dir}\\firefox_profile{profile_idx}_places.sqlite"
                remote_cookies = f"{remote_dir}\\firefox_profile{profile_idx}_cookies.sqlite"
                local_history = os.path.join(temp_dir, f"firefox_profile{profile_idx}_places.sqlite")
                local_cookies = os.path.join(temp_dir, f"firefox_profile{profile_idx}_cookies.sqlite")
                cmd = f"robocopy \"{profile_path}\" \"{remote_dir}\" places.sqlite /B /R:1 /W:1 >nul 2>&1"
                self._run_remote_command(hostname, username, password, cmd)
                cmd = f"if exist \"{remote_dir}\\places.sqlite\" ren \"{remote_dir}\\places.sqlite\" \"firefox_profile{profile_idx}_places.sqlite\" >nul 2>&1"
                self._run_remote_command(hostname, username, password, cmd)
                cmd = f"robocopy \"{profile_path}\" \"{remote_dir}\" cookies.sqlite /B /R:1 /W:1 >nul 2>&1"
                self._run_remote_command(hostname, username, password, cmd)
                cmd = f"if exist \"{remote_dir}\\cookies.sqlite\" ren \"{remote_dir}\\cookies.sqlite\" \"firefox_profile{profile_idx}_cookies.sqlite\" >nul 2>&1"
                self._run_remote_command(hostname, username, password, cmd)
                history_copied = self._copy_file_from_remote(hostname, username, password, remote_history, local_history)
                cookies_copied = self._copy_file_from_remote(hostname, username, password, remote_cookies, local_cookies)
                if history_copied and os.path.exists(local_history):
                    try:
                        conn = sqlite3.connect(local_history)
                        conn.row_factory = sqlite3.Row
                        cursor = conn.cursor()
                        cursor.execute("""
                        SELECT p.url, p.title, p.visit_count, h.visit_date, h.visit_type
                        FROM moz_places p
                        LEFT JOIN moz_historyvisits h ON p.id = h.place_id
                        WHERE p.url NOT LIKE 'moz-extension:%'
                        ORDER BY h.visit_date DESC
                        """)
                        for row in cursor.fetchall():
                            if row['visit_date']:
                                visit_time = datetime.datetime.fromtimestamp(row['visit_date'] / 1000000)
                                visit_time_str = visit_time.strftime('%Y-%m-%d %H:%M:%S')
                            else:
                                visit_time_str = None
                            result['history'].append({
                                'browser_name': 'firefox',
                                'url': row['url'],
                                'title': row['title'] or '',
                                'visit_count': row['visit_count'] or 0,
                                'visit_time': visit_time_str,
                                'visit_type': row['visit_type'],
                                'profile_path': profile_path
                            })
                        cursor.close()
                        conn.close()
                        logger.debug(f"Processed Firefox history for profile {profile_idx}")
                    except Exception as e:
                        logger.debug(f"Error processing Firefox history for profile {profile_idx}: {e}")
                if cookies_copied and os.path.exists(local_cookies):
                    try:
                        conn = sqlite3.connect(local_cookies)
                        conn.row_factory = sqlite3.Row
                        cursor = conn.cursor()
                        cursor.execute("""
                        SELECT name, value, host, path, expiry, lastAccessed, creationTime,
                               isSecure, isHttpOnly, sameSite
                        FROM moz_cookies
                        ORDER BY lastAccessed DESC
                        """)
                        for row in cursor.fetchall():
                            creation_time = datetime.datetime.fromtimestamp(row['creationTime'] / 1000000) if row['creationTime'] else None
                            last_accessed = datetime.datetime.fromtimestamp(row['lastAccessed'] / 1000000) if row['lastAccessed'] else None
                            expiry_time = datetime.datetime.fromtimestamp(row['expiry']) if row['expiry'] else None
                            result['cookies'].append({
                                'browser_name': 'firefox',
                                'creation_time': creation_time.strftime('%Y-%m-%d %H:%M:%S') if creation_time else None,
                                'host': row['host'],
                                'path': row['path'],
                                'name': row['name'],
                                'value': row['value'],
                                'expires': expiry_time.strftime('%Y-%m-%d %H:%M:%S') if expiry_time else None,
                                'secure': bool(row['isSecure']),
                                'http_only': bool(row['isHttpOnly']),
                                'last_access': last_accessed.strftime('%Y-%m-%d %H:%M:%S') if last_accessed else None,
                                'same_site': row['sameSite'],
                                'profile_path': profile_path
                            })
                        cursor.close()
                        conn.close()
                        logger.debug(f"Processed Firefox cookies for profile {profile_idx}")
                    except Exception as e:
                        logger.debug(f"Error processing Firefox cookies for profile {profile_idx}: {e}")
            logger.debug(f"Firefox extraction complete. History: {len(result['history'])}, Cookies: {len(result['cookies'])}")
            return result
        except Exception as e:
            logger.error(f"Error extracting Firefox data: {e}")
            return {'history': [], 'cookies': [], 'downloads': []}

    def _run_remote_command(self, hostname, username, password, command, get_output=False):
        """
        Run a command on a remote Windows system using the configured method.
        Args:
            hostname: Remote host
            username: Windows username  
            password: Windows password
            command: Command to execute
            get_output: Whether to return command output
        Returns:
            Command output if get_output=True, else None
        """
        try:
            if self.method == 'auto':
                for method in ['winrm', 'wmi', 'psexec']:
                    try:
                        return self._run_command_with_method(hostname, username, password, command, get_output, method)
                    except Exception as e:
                        logger.debug(f"Method {method} failed: {e}")
                        continue
                raise Exception("All methods failed")
            else:
                return self._run_command_with_method(hostname, username, password, command, get_output, self.method)
        except Exception as e:
            logger.debug(f"Error running remote command: {e}")
            if get_output:
                return ""
            return None

    def _run_command_with_method(self, hostname, username, password, command, get_output, method):
        """Run command using specific method."""
        if method == 'winrm':
            return self._run_winrm_command(hostname, username, password, command, get_output)
        elif method == 'wmi':
            return self._run_wmi_command(hostname, username, password, command, get_output)
        elif method == 'psexec':
            return self._run_psexec_command(hostname, username, password, command, get_output)
        elif method == 'ssh':
            return self._run_ssh_command(hostname, username, password, command, get_output)
        else:
            raise Exception(f"Unknown method: {method}")

    def _run_winrm_command(self, hostname, username, password, command, get_output):
        """Run command using WinRM (PowerShell Remoting) with multiple auth methods."""
        try:
            from pypsrp.client import Client
            # Try different authentication methods
            auth_methods = [
                {"auth": "basic", "ssl": False},
                {"auth": "ntlm", "ssl": False}, 
                {"auth": "negotiate", "ssl": False},
                {"auth": "basic", "ssl": True, "cert_validation": False}
            ]
            # Clean username - remove domain prefix if it's an IP
            clean_username = username
            if '\\' in username:
                domain, user = username.split('\\', 1)
                # If domain is an IP address, just use the username
                if self._is_ip_address(domain):
                    clean_username = user
                else:
                    clean_username = username  # Keep domain\user format
            last_error = None
            for auth_config in auth_methods:
                try:
                    logger.debug(f"Trying WinRM with auth: {auth_config}")
                    client = Client(
                        hostname, 
                        username=clean_username, 
                        password=password, 
                        **auth_config
                    )
                    if get_output:
                        stdout, stderr, rc = client.execute_cmd(f'cmd.exe /c "{command}"')
                        client.close()
                        return stdout.strip() if stdout else ""
                    else:
                        stdout, stderr, rc = client.execute_cmd(f'cmd.exe /c "{command}"')
                        client.close()
                        return None
                except Exception as e:
                    last_error = e
                    logger.debug(f"WinRM auth {auth_config['auth']} failed: {e}")
                    continue
            # If all methods failed, raise the last error
            raise last_error
        except ImportError:
            raise Exception("pypsrp library not available. Install with: pip install pypsrp")
        except Exception as e:
            logger.debug(f"Error running remote PowerShell command: {e}")
            raise
        
    def _run_wmi_command(self, hostname, username, password, command, get_output):
        """Run command using native WMI (Windows-to-Windows only)."""
        try:
            import wmi
            logger.debug(f"Connecting to {hostname} via WMI")
            connection = wmi.WMI(hostname, user=username, password=password)
            if get_output:
                temp_file = f"C:\\Windows\\Temp\\wmi_output_{int(time.time())}.txt"
                output_command = f'{command} > "{temp_file}" 2>&1'
                process_id, result = connection.Win32_Process.Create(CommandLine=f'cmd.exe /c "{output_command}"')
                if result == 0:
                    time.sleep(2)
                    try:
                        output = self._get_remote_file_content(hostname, username, password, temp_file)
                        connection.Win32_Process.Create(CommandLine=f'cmd.exe /c "del \\"{temp_file}\\""')
                        return output.strip() if output else ""
                    except Exception as e:
                        logger.debug(f"Error retrieving WMI command output: {e}")
                        return ""
                else:
                    logger.debug(f"WMI process creation failed with result code: {result}")
                    return ""
            else:
                process_id, result = connection.Win32_Process.Create(CommandLine=f'cmd.exe /c "{command}"')
                if result == 0:
                    logger.debug(f"WMI command executed successfully, process ID: {process_id}")
                    return None
                else:
                    logger.debug(f"WMI process creation failed with result code: {result}")
                    return None
        except ImportError:
            logger.error("WMI library not available. Install with: pip install wmi")
            if get_output:
                return ""
            return None
        except Exception as e:
            logger.debug(f"Error running WMI command: {e}")
            if get_output:
                return ""
            return None

    def _get_remote_file_content(self, hostname, username, password, remote_file):
        """Get the content of a remote file using UNC path."""
        try:
            unc_path = remote_file.replace('C:', f'\\\\{hostname}\\C$')
            net_use_cmd = f'net use \\\\{hostname}\\C$ /user:{username} {password}'
            subprocess.run(net_use_cmd, shell=True, capture_output=True)
            try:
                with open(unc_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except:
                with open(unc_path, 'r', encoding='cp1252', errors='ignore') as f:
                    content = f.read()
            subprocess.run(f'net use \\\\{hostname}\\C$ /delete /y', shell=True, capture_output=True)
            return content
        except Exception as e:
            logger.debug(f"Error reading remote file content: {e}")
            return ""

    def _copy_file_from_remote(self, hostname, username, password, remote_path, local_path):
        """Copy a file from remote system to local system."""
        try:
            unc_path = remote_path.replace('C:', f'\\\\{hostname}\\C$')
            net_use_cmd = f'net use \\\\{hostname}\\C$ /user:{username} {password}'
            result = subprocess.run(net_use_cmd, shell=True, capture_output=True)
            if result.returncode != 0:
                logger.debug(f"Failed to create network connection: {result.stderr.decode()}")
                return False
            try:
                shutil.copy2(unc_path, local_path)
                logger.debug(f"Successfully copied {remote_path} to {local_path}")
                success = True
            except Exception as e:
                logger.debug(f"File copy failed: {e}")
                success = False
            subprocess.run(f'net use \\\\{hostname}\\C$ /delete /y', shell=True, capture_output=True)
            return success
        except Exception as e:
            logger.debug(f"Error in file copy operation: {e}")
            return False

    def _run_psexec_command(self, hostname, username, password, command, get_output):
        """Run a command using PSEXEC (fallback method)."""
        try:
            if get_output:
                result = subprocess.run([
                    "psexec", f"\\\\{hostname}", "-u", username, "-p", password, 
                    "cmd", "/c", command
                ], capture_output=True, text=True, check=False)
                return result.stdout.strip() if result.stdout else ""
            else:
                subprocess.run([
                    "psexec", f"\\\\{hostname}", "-u", username, "-p", password, 
                    "cmd", "/c", command
                ], capture_output=True, check=False)
                return None
        except Exception as e:
            logger.debug(f"Error running PSEXEC command: {e}")
            if get_output:
                return ""
            return None

    def _run_ssh_command(self, hostname, username, password, command, get_output):
        """Run command using SSH (for Windows with OpenSSH)."""
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname, username=username, password=password)
            stdin, stdout, stderr = ssh.exec_command(command)
            if get_output:
                output = stdout.read().decode()
                ssh.close()
                return output
            else:
                ssh.close()
                return None
        except Exception as e:
            logger.debug(f"SSH command failed: {e}")
            raise