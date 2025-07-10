# ============================================================================
# api_reputation.py
# ============================================================================

"""
API-based URL reputation services module for browsertriage.
Currently supports VirusTotal API for URL reputation checking.
"""

import os
import time
import logging
from abc import ABC, abstractmethod
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)

class ReputationResult:
    """Standardized result object for URL reputation checks."""
    
    def __init__(self, url, service):
        self.url = url
        self.service = service
        self.is_malicious = False
        self.is_suspicious = False
        self.is_clean = True
        self.confidence_score = 0.0  # 0.0 to 1.0
        self.categories = []
        self.threat_types = []
        self.last_analysis_date = None
        self.additional_info = {}
        self.error_message = None
        self.rate_limited = False
    
    def to_dict(self):
        """Convert result to dictionary for easy serialization."""
        return {
            'url': self.url,
            'service': self.service,
            'is_malicious': self.is_malicious,
            'is_suspicious': self.is_suspicious,
            'is_clean': self.is_clean,
            'confidence_score': self.confidence_score,
            'categories': self.categories,
            'threat_types': self.threat_types,
            'last_analysis_date': self.last_analysis_date,
            'additional_info': self.additional_info,
            'error_message': self.error_message,
            'rate_limited': self.rate_limited
        }
    
    def get_risk_level(self):
        """Get a simple risk level assessment."""
        if self.is_malicious:
            return "HIGH"
        elif self.is_suspicious:
            return "MEDIUM" 
        elif self.confidence_score > 0.7:
            return "LOW"
        else:
            return "UNKNOWN"

class APIServiceBase(ABC):
    """Abstract base class for API-based URL reputation services."""
    
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.service_name = self.__class__.__name__.replace('Service', '')
        self.rate_limit_delay = 1.0  # Default delay between requests
        self.last_request_time = 0.0
        
    @abstractmethod
    def check_url(self, url):
        """
        Check the reputation of a single URL.
        Args:
            url: URL to check
        Returns:
            ReputationResult: Standardized result object
        """
        pass
    
    def check_urls_batch(self, urls):
        """
        Check multiple URLs. Default implementation calls check_url for each.
        Override in subclasses that support batch operations.
        Args:
            urls: List of URLs to check
        Returns:
            List[ReputationResult]: Results for each URL
        """
        results = []
        for url in urls:
            # Respect rate limits
            self._wait_for_rate_limit()
            result = self.check_url(url)
            results.append(result)
        return results
    
    def _wait_for_rate_limit(self):
        """Enforce rate limiting between requests."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - time_since_last
            logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
        self.last_request_time = time.time()
    
    def is_configured(self):
        """Check if the service is properly configured."""
        return self.api_key is not None and len(self.api_key.strip()) > 0

class VirusTotalService(APIServiceBase):
    """VirusTotal URL reputation service implementation using the free API tier."""
    
    def __init__(self, api_key=None):
        super().__init__(api_key)
        # Free tier: 4 requests per minute (15 second intervals)
        self.rate_limit_delay = 15.0
        self.client = None
        # Initialize the VT client if API key is provided
        if self.api_key:
            try:
                import vt
                self.client = vt.Client(self.api_key)
                logger.info("VirusTotal client initialized successfully (Free API)")
            except ImportError:
                logger.error("VirusTotal library not found. Install with: pip install vt-py")
            except Exception as e:
                logger.error(f"Error initializing VirusTotal client: {e}")
    
    @staticmethod
    def estimate_completion_time(url_count):
        """
        Estimate how long it will take to check all URLs with the free API.
        Args:
            url_count: Number of URLs to check
        Returns:
            String describing estimated time
        """
        # Free tier: 4 requests per minute
        minutes = url_count / 4
        hours = minutes / 60
        if hours >= 1:
            return f"approximately {hours:.1f} hours ({minutes:.0f} minutes)"
        elif minutes >= 1:
            return f"approximately {minutes:.0f} minutes"
        else:
            return "less than 1 minute"
    
    @staticmethod
    def get_rate_limit_warning(url_count):
        """
        Get a warning message about rate limits for the given number of URLs.
        Args:
            url_count: Number of URLs to check
        Returns:
            Warning message string
        """
        estimate = VirusTotalService.estimate_completion_time(url_count)
        return f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                           VIRUSTOTAL FREE API WARNING                        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ You are using the VirusTotal FREE API tier with the following limitations:   ║
║                                                                              ║
║ • Rate Limit: 4 requests per minute (15 second intervals)                   ║
║ • URLs to check: {url_count:<58} ║
║ • Estimated time: {estimate:<56} ║
║                                                                              ║
║ The analysis will pause 15 seconds between each URL check to respect        ║
║ VirusTotal's rate limits. You can stop the process at any time with Ctrl+C. ║
║                                                                              ║
║ For faster analysis, consider:                                               ║
║ • Using only local MBL checking (-m option)                                 ║
║ • Filtering to specific browsers/users to reduce URL count                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    
    def check_url(self, url):
        """Check URL reputation using VirusTotal API with the official vt library."""
        result = ReputationResult(url, "VirusTotal")
        if not self.is_configured():
            result.error_message = "VirusTotal API key not configured"
            return result
        if not self.client:
            result.error_message = "VirusTotal client not initialized. Install vt-py library."
            return result
        try:
            import vt
            # Get URL ID (VT uses base64url encoded URLs as IDs)
            url_id = vt.url_id(url)
            # Get URL analysis
            try:
                url_obj = self.client.get_object(f"/urls/{url_id}")
            except vt.APIError as e:
                if e.code == "NotFoundError":
                    # URL not found in VirusTotal database
                    result.error_message = "URL not found in VirusTotal database"
                    return result
                elif e.code == "QuotaExceededError":
                    result.rate_limited = True
                    result.error_message = "VirusTotal rate limit exceeded"
                    return result
                else:
                    result.error_message = f"VirusTotal API error: {e.code} - {e.message}"
                    return result
            # Parse VirusTotal response
            stats = url_obj.last_analysis_stats
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            undetected = stats.get('undetected', 0)
            harmless = stats.get('harmless', 0)
            total_engines = malicious + suspicious + undetected + harmless
            if total_engines > 0:
                # Calculate confidence score (higher when fewer engines detect as malicious)
                result.confidence_score = (harmless + undetected) / total_engines
                if malicious > 0:
                    if malicious >= 3:  # 3+ engines flagged as malicious
                        result.is_malicious = True
                        result.is_clean = False
                    else:
                        result.is_suspicious = True
                        result.is_clean = False
                elif suspicious > 0:
                    result.is_suspicious = True
                    result.is_clean = False
                else:
                    result.is_clean = True
                # Extract additional information
                result.additional_info = {
                    'malicious_engines': malicious,
                    'suspicious_engines': suspicious,
                    'harmless_engines': harmless,
                    'undetected_engines': undetected,
                    'total_engines': total_engines,
                    'last_analysis_date': str(url_obj.last_analysis_date) if hasattr(url_obj, 'last_analysis_date') else None,
                    'reputation': getattr(url_obj, 'reputation', None),
                    'times_submitted': getattr(url_obj, 'times_submitted', None)
                }
                # Extract threat types and categories
                if hasattr(url_obj, 'last_analysis_results'):
                    threat_types = set()
                    categories = set()
                    for engine_name, engine_result in url_obj.last_analysis_results.items():
                        if engine_result.get('category') in ['malicious', 'suspicious']:
                            result_text = engine_result.get('result', '').lower()
                            # Categorize threats
                            if any(term in result_text for term in ['malware', 'trojan', 'virus']):
                                threat_types.add('malware')
                            elif any(term in result_text for term in ['phishing', 'phish']):
                                threat_types.add('phishing')
                            elif any(term in result_text for term in ['spam', 'unwanted']):
                                threat_types.add('spam')
                            elif 'suspicious' in result_text:
                                threat_types.add('suspicious')
                            # Add engine-specific categories
                            if engine_result.get('result'):
                                categories.add(engine_result['result'])
                    result.threat_types = list(threat_types)
                    result.categories = list(categories)[:5]  # Limit to top 5 categories
                # Set analysis date
                if hasattr(url_obj, 'last_analysis_date'):
                    result.last_analysis_date = str(url_obj.last_analysis_date)
        except ImportError:
            result.error_message = "VirusTotal library not available. Install with: pip install vt-py"
        except Exception as e:
            result.error_message = f"VirusTotal check failed: {str(e)}"
        return result
    
    def __del__(self):
        """Close the VirusTotal client when the service is destroyed."""
        if self.client:
            try:
                self.client.close()
            except:
                pass  # Ignore errors during cleanup