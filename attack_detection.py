"""
Enhanced detection engine module for browsertriage.
Provides detection capabilities for various attack types and threat indicators.
Now includes comprehensive URL encoding/decoding support.
"""

import re
import logging
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class DetectionResult:
    """Result object for detection findings."""
    detection_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float  # 0.0 to 1.0
    description: str
    evidence: list
    mitigation: str = None
    references: list = None

class WebAttackDetector:
    """Detector for web-based attack patterns in URLs and parameters with URL encoding support."""
    
    def __init__(self):
        # XSS Detection Patterns (both unencoded and encoded versions)
        # Note: Patterns are designed to match XSS content anywhere within parameters
        self.xss_patterns = [
            # Script injection - unencoded (more flexible matching)
            r'<script[^>]*>.*?</script>',
            r'<script[^>]*>',  # Script tag without closing
            r'</script>',      # Closing script tag
            r'javascript:',
            r'vbscript:',
            r'onload\s*=',
            r'onerror\s*=',
            r'onclick\s*=',
            r'onmouseover\s*=',
            r'onsubmit\s*=',
            r'onfocus\s*=',
            r'onblur\s*=',
            
            # Script injection - URL encoded (more flexible)
            r'%3Cscript[^%3E>]*%3E.*?%3C/script%3E',  # Full script tags
            r'%3Cscript[^%3E>]*%3E',                   # Opening script tag
            r'%3C/script%3E',                          # Closing script tag
            r'%3Cscript[^>]*>.',           # Mixed encoding
            r'<img[^>]*onerror',             # Unencoded img onerror
            r'%3Cbody[^%3E>]*onload',
            r'<body[^>]*onload',
            r'%3Csvg[^%3E>]*onload',
            r'<svg[^>]*onload',
            r'%3Ciframe[^%3E>]*src%3Djavascript',
            r'<iframe[^>]*src=javascript',
            r'%3Cobject[^%3E>]*data%3Djavascript',
            r'<object[^>]*data=javascript',
            r'%3Cembed[^%3E>]*src%3Djavascript',
            r'<embed[^>]*src=javascript',
            
            # Advanced XSS patterns
            r'expression\s*\(',              # CSS expression
            r'expression%20*\(',
            r'behavior\s*:',                 # CSS behavior
            r'behavior%20*:',
            r'-moz-binding\s*:',             # Mozilla binding
            r'-moz-binding%20*:',
            r'@import\s*["\']javascript:',   # CSS @import
            r'@import%20*["\']javascript:',
            
            # Data URI XSS
            r'data:[^;]*;base64,[A-Za-z0-9+/=]*',
            r'data%3A[^%3B]*%3Bbase64%2C[A-Za-z0-9%2B/=]*',
            r'data:[^;]*javascript',
            r'data%3A[^%3B]*javascript',
        ]
        
        # SQL Injection Detection Patterns (both unencoded and encoded)
        self.sqli_patterns = [
            # Basic SQL injection - unencoded
            r".*?'.*?(union|select|insert|update|delete|drop|create|alter|exec|execute)",
            r'.*?".*?(union|select|insert|update|delete|drop|create|alter|exec|execute)',
            
            # Basic SQL injection - URL encoded
            r".*?%27.*?(union|select|insert|update|delete|drop|create|alter|exec|execute)",
            r".*?%22.*?(union|select|insert|update|delete|drop|create|alter|exec|execute)",
            r".*?'.*?(union|select|insert|update|delete|drop|create|alter|exec|execute)",  # Mixed
            
            # SQL operators - unencoded
            r".*?'.*?(or|and).*?[=<>]",
            r'.*?".*?(or|and).*?[=<>]',
            
            # SQL operators - URL encoded
            r".*?%27.*?(or|and).*?[%3D%3C%3E=<>]",
            r".*?%22.*?(or|and).*?[%3D%3C%3E=<>]",
            r".*?'.*?(or|and).*?[%3D%3C%3E=<>]",  # Mixed
            
            # SQL comments - unencoded
            r".*?'.*?--",
            r'.*?".*?--',
            r".*?'.*?/\*.*?\*/",
            r'.*?".*?/\*.*?\*/',
            
            # SQL comments - URL encoded
            r".*?%27.*?--",
            r".*?%27.*?%2D%2D",
            r".*?%22.*?--",
            r".*?%22.*?%2D%2D",
            r".*?'.*?%2D%2D",  # Mixed
            r".*?%27.*?%2F%2A.*?%2A%2F",
            r".*?%22.*?%2F%2A.*?%2A%2F",
            
            # SQL functions - unencoded
            r".*?'.*?(count|length|substring|ascii|char|concat)",
            r'.*?".*?(count|length|substring|ascii|char|concat)',
            
            # SQL functions - URL encoded
            r".*?%27.*?(count|length|substring|ascii|char|concat)",
            r".*?%22.*?(count|length|substring|ascii|char|concat)",
            
            # Time-based injection patterns - unencoded
            r".*?'.*?(sleep|benchmark|waitfor|delay)",
            r'.*?".*?(sleep|benchmark|waitfor|delay)',
            
            # Time-based injection patterns - URL encoded
            r".*?%27.*?(sleep|benchmark|waitfor|delay)",
            r".*?%22.*?(sleep|benchmark|waitfor|delay)",
            
            # Boolean-based injection patterns - unencoded
            r".*?'.*?(true|false).*?[=<>].*?(true|false)",
            r'.*?".*?(true|false).*?[=<>].*?(true|false)',
            
            # Boolean-based injection patterns - URL encoded
            r".*?%27.*?(true|false).*?[%3D%3C%3E=<>].*?(true|false)",
            r".*?%22.*?(true|false).*?[%3D%3C%3E=<>].*?(true|false)",
            
            # Error-based injection patterns - unencoded
            r".*?'.*?(error|exception|invalid)",
            r'.*?".*?(error|exception|invalid)',
            
            # Error-based injection patterns - URL encoded
            r".*?%27.*?(error|exception|invalid)",
            r".*?%22.*?(error|exception|invalid)",
        ]
        
        # CSRF Detection Patterns - IMPROVED
        self.csrf_patterns = [
            # State-changing parameter names (broader patterns)
            r'[?&]\w*change\w*=',           # Catches "Change=Change"
            r'[?&]\w*password\w*=',         # Catches "password_new="
            r'[?&]\w*delete\w*=',
            r'[?&]\w*remove\w*=', 
            r'[?&]\w*update\w*=',
            r'[?&]\w*modify\w*=',
            r'[?&]\w*edit\w*=',
            
            # State-changing values
            r'[?&]\w+=(delete|remove|update|change|modify|edit|create|add)',
            
            # Redirect patterns (common in CSRF)
            r'[?&](next|redirect|return_to|callback)=https?://',  # Catches "next=https://..."
            
            # Common CSRF operations
            r'[?&](action|cmd|method)=.*?(delete|remove|transfer|change|update)',
            r'[?&](confirm|submit|save|apply|execute)=',
            
            # URL encoded versions
            r'[?&]%5Cw%2Achange%5Cw%2A%3D',
            r'[?&]%5Cw%2Apassword%5Cw%2A%3D',
            r'[?&](next|redirect)%3Dhttps%3F%3A%2F%2F',
        ]
        
        # Compile patterns with case-insensitive flag
        self.compiled_xss = [re.compile(pattern, re.IGNORECASE) for pattern in self.xss_patterns]
        self.compiled_sqli = [re.compile(pattern, re.IGNORECASE) for pattern in self.sqli_patterns]
        self.compiled_csrf = [re.compile(pattern, re.IGNORECASE) for pattern in self.csrf_patterns]
    
    def _decode_url_variants(self, text):
        """Generate multiple decoded variants of a URL/parameter for comprehensive checking."""
        variants = [text]
        # URL decode once
        try:
            decoded_once = urllib.parse.unquote(text)
            if decoded_once != text:
                variants.append(decoded_once)
                # URL decode twice (for double encoding)
                decoded_twice = urllib.parse.unquote(decoded_once)
                if decoded_twice != decoded_once:
                    variants.append(decoded_twice)
        except:
            pass
        # Plus decoding (+ to space)
        try:
            plus_decoded = text.replace('+', ' ')
            if plus_decoded != text:
                variants.append(plus_decoded)
                # Combine plus and URL decoding
                plus_url_decoded = urllib.parse.unquote(plus_decoded)
                if plus_url_decoded != plus_decoded:
                    variants.append(plus_url_decoded)
        except:
            pass
        return variants
    
    def _check_patterns_comprehensive(self, text, compiled_patterns, detection_type):
        """
        Check text against patterns using multiple URL decoding variants.
        Args:
            text: Text to check
            compiled_patterns: List of compiled regex patterns
            detection_type: Type of detection (for logging)
        Returns:
            Tuple of (match_found, matched_variant, pattern_index)
        """
        variants = self._decode_url_variants(text)
        for variant in variants:
            for pattern_idx, pattern in enumerate(compiled_patterns):
                if pattern.search(variant):
                    logger.debug(f"{detection_type} pattern matched in variant: {variant[:100]}...")
                    return True, variant, pattern_idx
        return False, None, None
    
    def _check_patterns_with_variants(self, text, compiled_patterns):
        """Check text against patterns using URL decoding variants."""
        variants = self._decode_url_variants(text)
        for variant in variants:
            for pattern in compiled_patterns:
                if pattern.search(variant):
                    return True, variant
        return False, text
    
    def detect_xss(self, url):
        """Detect potential XSS attacks in URL with comprehensive encoding support."""
        detections = []
        try:
            # First check the entire URL for XSS patterns (for fragment-based XSS)
            url_variants = self._decode_url_variants(url)
            for variant in url_variants:
                for pattern_idx, pattern in enumerate(self.compiled_xss):
                    if pattern.search(variant):
                        evidence = [
                            f"XSS pattern found in URL: {url[:100]}",
                            f"Matched in decoded form: {variant[:100]}"
                        ]  
                        # Determine severity
                        if pattern_idx < 10:  # Script injection patterns
                            severity = "HIGH"
                            confidence = 0.9
                        elif pattern_idx < 25:  # Event handler patterns
                            severity = "MEDIUM"
                            confidence = 0.8
                        else:  # Other patterns
                            severity = "MEDIUM"
                            confidence = 0.7
                        # Increase confidence if encoding was detected
                        if variant != url:
                            evidence.append("URL encoding detected - potential evasion attempt")
                            confidence = min(1.0, confidence + 0.1)
                        detections.append(DetectionResult(
                            detection_type="XSS",
                            severity=severity,
                            confidence=confidence,
                            description=f"Potential Cross-Site Scripting (XSS) attack detected in URL",
                            evidence=evidence,
                            mitigation="Validate and sanitize all user input. Use Content Security Policy (CSP). Implement proper output encoding.",
                            references=["https://owasp.org/www-community/attacks/xss/"]
                        ))
                        break  # Only report once per URL
            # Also check individual parameters (original logic)
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for param_name, param_values in query_params.items():
                for param_value in param_values:
                    # Check parameter value against all XSS patterns
                    match_found, matched_variant, pattern_idx = self._check_patterns_comprehensive(
                        param_value, self.compiled_xss, "XSS"
                    )
                    if match_found:
                        evidence = [
                            f"Parameter '{param_name}' contains potential XSS: {param_value[:100]}",
                            f"Matched pattern in decoded form: {matched_variant[:100]}"
                        ]
                        # Determine severity based on pattern type
                        if pattern_idx < 10:  # Script injection patterns
                            severity = "HIGH"
                            confidence = 0.9
                        elif pattern_idx < 25:  # Event handler patterns
                            severity = "MEDIUM"
                            confidence = 0.8
                        else:  # Other patterns
                            severity = "MEDIUM"
                            confidence = 0.7
                        # Increase confidence if encoding was detected
                        if matched_variant != param_value:
                            evidence.append("URL encoding detected - potential evasion attempt")
                            confidence = min(1.0, confidence + 0.1)
                        detections.append(DetectionResult(
                            detection_type="XSS",
                            severity=severity,
                            confidence=confidence,
                            description=f"Potential Cross-Site Scripting (XSS) attack detected in URL parameter",
                            evidence=evidence,
                            mitigation="Validate and sanitize all user input. Use Content Security Policy (CSP). Implement proper output encoding.",
                            references=["https://owasp.org/www-community/attacks/xss/"]
                        ))
                        break  # Only report once per parameter
        except Exception as e:
            logger.debug(f"Error parsing URL for XSS detection: {e}")
        return detections

    def detect_sqli(self, url):
        """Detect potential SQL injection attacks in URL with comprehensive encoding support."""
        detections = []
        detected_patterns = set()  # Track patterns found for this URL
        try:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for param_name, param_values in query_params.items():
                for param_value in param_values:
                    # Check parameter value against all SQLi patterns
                    match_found, matched_variant, pattern_idx = self._check_patterns_comprehensive(
                        param_value, self.compiled_sqli, "SQLi"
                    )
                    if match_found:
                        # Create unique pattern key (like XSS does implicitly)
                        pattern_key = f"{param_name}:{pattern_idx}"
                        if pattern_key not in detected_patterns:
                            detected_patterns.add(pattern_key)
                            evidence = [
                                f"SQL injection pattern found in URL: {url[:100]}",
                                f"Parameter '{param_name}' contains potential SQL injection: {param_value[:100]}",
                                f"Matched pattern in decoded form: {matched_variant[:100]}"
                            ]
                            # Determine severity based on pattern type
                            if pattern_idx < 8:  # Basic SQL injection patterns
                                severity = "HIGH"
                                confidence = 0.9
                            elif pattern_idx < 20:  # SQL operators and comments
                                severity = "HIGH"
                                confidence = 0.8
                            else:  # Other patterns
                                severity = "MEDIUM"
                                confidence = 0.7
                            # Increase confidence if encoding was detected
                            if matched_variant != param_value:
                                evidence.append("URL encoding detected - potential evasion attempt")
                                confidence = min(1.0, confidence + 0.1)
                            detections.append(DetectionResult(
                                detection_type="SQLi",
                                severity=severity,
                                confidence=confidence,
                                description=f"Potential SQL Injection attack detected in URL parameter",
                                evidence=evidence,
                                mitigation="Use parameterized queries and input validation. Apply principle of least privilege to database access. Implement WAF rules.",
                                references=["https://owasp.org/www-community/attacks/SQL_Injection"]
                            ))
                        break  # Always break after any match (like XSS does)
        except Exception as e:
            logger.debug(f"Error parsing URL for SQLi detection: {e}")
        return detections
        
    def detect_csrf(self, url):
        """Detect potential CSRF attack indicators in URL with encoding support."""
        detections = []
        # Check for suspicious patterns in URL variants
        match_found, matched_variant, pattern_idx = self._check_patterns_comprehensive(
            url, self.compiled_csrf, "CSRF"
        )
        if match_found:
            evidence = [f"URL contains potential CSRF pattern: {url[:100]}"]
            if matched_variant != url:
                evidence.append(f"Pattern matched in decoded form: {matched_variant[:100]}")
                evidence.append("URL encoding detected in CSRF pattern")
            detections.append(DetectionResult(
                detection_type="CSRF",
                severity="MEDIUM",
                confidence=0.6,  # Lower confidence as these are indirect indicators
                description="Potential Cross-Site Request Forgery (CSRF) attack indicators detected",
                evidence=evidence,
                mitigation="Implement CSRF tokens, verify referrer headers, use SameSite cookies. Validate all state-changing requests.",
                references=["https://owasp.org/www-community/attacks/csrf"]
            ))
        return detections

class ThreatCategoryDetector:
    """Detector for various threat categories based on URL characteristics with encoding support."""
    def __init__(self):
        """Initialize ThreatCategoryDetector with encoding-aware regex patterns."""
        # Phishing indicators with URL encoding support
        self.phishing_indicators = {
            'suspicious_domains': [
                # Typosquatting patterns - unencoded
                r'g[o0][o0]gle',
                r'fac[e3]b[o0]{2}k',
                r'tw[i1]tt[e3]r',
                r'amaz[o0]n',
                r'payp[a4]l',
                r'micr[o0]s[o0]ft',
                r'app1e',  # apple with 1 instead of l
                r'bank[o0]famerica',
                r'w[e3]lls[-_]?farg[o0]',
                
                # Typosquatting patterns - URL encoded
                r'g%5Bo0%5D%5Bo0%5Dgle',
                r'fac%5Be3%5Db%5Bo0%5D%7B2%7Dk',
                
                # Suspicious TLDs for financial services
                r'(bank|pay|secure|login|account).*\.(tk|ml|ga|cf)',
                r'%28bank%7Cpay%7Csecure%7Clogin%7Caccount%29.*%2E%28tk%7Cml%7Cga%7Ccf%29',
            ],
            'suspicious_paths': [
                # Unencoded patterns
                r'/secure[_-]?(login|update|verify)',
                r'/account[_-]?(suspended|locked|verify)',
                r'/urgent[_-]?action',
                r'/click[_-]?here',
                r'/limited[_-]?time',
                r'/verify[_-]?identity',
                r'/update[_-]?payment',
                
                # URL encoded patterns
                r'%2Fsecure[_-]%3F%28login%7Cupdate%7Cverify%29',
                r'%2Faccount[_-]%3F%28suspended%7Clocked%7Cverify%29',
                r'%2Furgent[_-]%3Faction',
                r'%2Fclick[_-]%3Fhere',
                r'%2Flimited[_-]%3Ftime',
                r'%2Fverify[_-]%3Fidentity',
                r'%2Fupdate[_-]%3Fpayment',
            ],
            'suspicious_params': [
                # Unencoded patterns
                r'token=[a-zA-Z0-9]{20,}',
                r'redirect_uri=.*?(bit\.ly|tinyurl|t\.co)',
                r'next=https?://(?!.*(?:google|facebook|microsoft))',
                
                # URL encoded patterns
                r'token%3D[a-zA-Z0-9]{20,}',
                r'redirect_uri%3D.*?%28bit%5C%2Ely%7Ctinyurl%7Ct%5C%2Eco%29',
                r'next%3Dhttps%3F%3A%2F%2F(?!.*(?:google|facebook|microsoft))',
            ]
        }
        
        # Malware download indicators with URL encoding
        self.malware_indicators = {
            'suspicious_file_extensions': [
                # Unencoded patterns
                r'\.(exe|scr|bat|cmd|com|pif|vbs|js|jar|apk|dmg|ps1|sh|py)(\?|$)',
                r'\.(zip|rar|7z|tar\.gz).*\.(exe|scr|bat)',  # Archive with executable
                
                # URL encoded patterns
                r'%2E%28exe%7Cscr%7Cbat%7Ccmd%7Ccom%7Cpif%7Cvbs%7Cjs%7Cjar%7Capk%7Cdmg%29%28%5C%3F%7C%24%29',
                r'%2E%28zip%7Crar%7C7z%7Ctar%5C%2Egz%29.*%2E%28exe%7Cscr%7Cbat%29',
            ],
            'suspicious_download_patterns': [
                # Unencoded patterns
                r'/download/.*\.(exe|scr|bat)',
                r'/files/.*\.(exe|scr|bat)',
                r'/attachment/.*\.(exe|scr|bat)',
                r'filename=.*\.(exe|scr|bat)',
                
                # URL encoded patterns
                r'%2Fdownload%2F.*%2E%28exe%7Cscr%7Cbat%29',
                r'%2Ffiles%2F.*%2E%28exe%7Cscr%7Cbat%29',
                r'%2Fattachment%2F.*%2E%28exe%7Cscr%7Cbat%29',
                r'filename%3D.*%2E%28exe%7Cscr%7Cbat%29',
            ],
            'c2_patterns': [
                # Unencoded patterns
                r'/[a-f0-9]{32,}',  # Long hex strings (potential session IDs)
                r'/api/v[0-9]+/[a-f0-9]+',  # API endpoints with hex
                r'/[a-zA-Z0-9]{20,}\.(txt|php|asp)',  # Suspicious file patterns
                r'[?&](cmd|exec|shell|system)=',  # Command execution parameters
                
                # URL encoded patterns
                r'%2F[a-f0-9]{32,}',
                r'%2Fapi%2Fv[0-9]%2B%2F[a-f0-9]%2B',
                r'%2F[a-zA-Z0-9]{20,}%2E%28txt%7Cphp%7Casp%29',
                r'[?&]%28cmd%7Cexec%7Cshell%7Csystem%29%3D',
            ]
        }
        
        # Social engineering indicators
        self.social_engineering_patterns = [
            # Urgency and fear tactics
            r'(urgent|immediate|expire|suspend|limited|act now|verify now)',
            r'(account.*suspend|payment.*fail|security.*breach|unauthorized.*access)',
            r'(click.*here.*now|respond.*immediately|update.*payment)',
            
            # URL encoded versions
            r'%28urgent%7Cimmediate%7Cexpire%7Csuspend%7Climited%7Cact%20now%7Cverify%20now%29',
            r'%28account.*suspend%7Cpayment.*fail%7Csecurity.*breach%7Cunauthorized.*access%29',
        ]
        
        # Compile all patterns
        self.compiled_phishing = {}
        for category, patterns in self.phishing_indicators.items():
            self.compiled_phishing[category] = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
        self.compiled_malware = {}
        for category, patterns in self.malware_indicators.items():
            self.compiled_malware[category] = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
        self.compiled_social_eng = [re.compile(pattern, re.IGNORECASE) for pattern in self.social_engineering_patterns]
    
    def _decode_url_variants(self, text):
        """Generate multiple decoded variants of a URL/parameter for comprehensive checking."""
        variants = [text]
        # URL decode once
        try:
            decoded_once = urllib.parse.unquote(text)
            if decoded_once != text:
                variants.append(decoded_once)
                # URL decode twice (for double encoding)
                decoded_twice = urllib.parse.unquote(decoded_once)
                if decoded_twice != decoded_once:
                    variants.append(decoded_twice)
        except:
            pass
        # Plus decoding (+ to space)
        try:
            plus_decoded = text.replace('+', ' ')
            if plus_decoded != text:
                variants.append(plus_decoded)
                # Combine plus and URL decoding
                plus_url_decoded = urllib.parse.unquote(plus_decoded)
                if plus_url_decoded != plus_decoded:
                    variants.append(plus_url_decoded)
        except:
            pass
        return variants
    
    def _check_patterns_with_variants(self, text, compiled_patterns):
        """Check text against patterns using URL decoding variants."""
        variants = self._decode_url_variants(text)
        for variant in variants:
            for pattern in compiled_patterns:
                if pattern.search(variant):
                    return True, variant
        return False, text
    
    def detect_phishing(self, url):
        """Detect phishing indicators in URL with encoding support."""
        detections = []
        for category, patterns in self.compiled_phishing.items():
            match_found, matched_variant = self._check_patterns_with_variants(url, patterns)
            if match_found:
                evidence = [f"URL matches phishing pattern ({category}): {url[:100]}"]
                if matched_variant != url:
                    evidence.append(f"Pattern matched in decoded form: {matched_variant[:100]}")
                    evidence.append("URL encoding detected in phishing pattern")
                detections.append(DetectionResult(
                    detection_type="Phishing",
                    severity="HIGH",
                    confidence=0.7,
                    description=f"Potential phishing attempt detected ({category})",
                    evidence=evidence,
                    mitigation="Verify the legitimacy of the website through official channels. Do not enter sensitive information."
                ))
                break
        return detections
    
    def detect_malware_download(self, url, filename=None):
        """Detect malware download indicators with encoding support."""
        detections = []
        # Check URL for malware patterns
        for category, patterns in self.compiled_malware.items():
            url_match, matched_variant = self._check_patterns_with_variants(url, patterns)
            if url_match:
                severity = "HIGH" if "exe" in str(patterns) else "MEDIUM"
                evidence = [f"URL matches malware pattern: {url[:100]}"]
                if matched_variant != url:
                    evidence.append(f"Pattern matched in decoded form: {matched_variant[:100]}")
                    evidence.append("URL encoding detected in malware pattern")
                detections.append(DetectionResult(
                    detection_type="Malware Download",
                    severity=severity,
                    confidence=0.8,
                    description=f"Potential malware download detected ({category})",
                    evidence=evidence,
                    mitigation="Scan downloaded files with antivirus software. Avoid downloading executables from untrusted sources."
                ))
                break
        # Check filename if provided
        if filename:
            filename_match, matched_variant = self._check_patterns_with_variants(
                filename.lower(), self.compiled_malware['suspicious_file_extensions']
            )
            if filename_match:
                evidence = [f"Suspicious filename: {filename}"]
                if matched_variant != filename.lower():
                    evidence.append(f"Pattern matched in decoded form: {matched_variant}")
                detections.append(DetectionResult(
                    detection_type="Malware Download",
                    severity="HIGH",
                    confidence=0.9,
                    description="Potentially dangerous file type downloaded",
                    evidence=evidence,
                    mitigation="Exercise extreme caution with executable files. Verify source and scan before opening."
                ))
        return detections
    
    def detect_c2_communication(self, url):
        """Detect potential Command & Control (C2) communication patterns with encoding support."""
        detections = []
        c2_match, matched_variant = self._check_patterns_with_variants(
            url, self.compiled_malware['c2_patterns']
        )
        if c2_match:
            evidence = [f"URL matches C2 pattern: {url[:100]}"]
            if matched_variant != url:
                evidence.append(f"Pattern matched in decoded form: {matched_variant[:100]}")
                evidence.append("URL encoding detected in C2 pattern")
            detections.append(DetectionResult(
                detection_type="C2 Communication",
                severity="CRITICAL",
                confidence=0.7,
                description="Potential Command & Control communication detected",
                evidence=evidence,
                mitigation="Isolate system immediately. Run full malware scan and check for compromise indicators."
            ))
        return detections
    
    def detect_social_engineering(self, url, title=None):
        """Detect social engineering indicators with encoding support."""
        detections = []
        content_to_check = [url]
        if title:
            content_to_check.append(title)
        for content in content_to_check:
            if not content:
                continue
            social_match, matched_variant = self._check_patterns_with_variants(
                content, self.compiled_social_eng
            )
            if social_match:
                evidence = [f"Suspicious content: {content[:100]}"]
                if matched_variant != content:
                    evidence.append(f"Pattern matched in decoded form: {matched_variant[:100]}")
                    evidence.append("URL encoding detected in social engineering content")
                detections.append(DetectionResult(
                    detection_type="Social Engineering",
                    severity="MEDIUM",
                    confidence=0.6,
                    description="Social engineering tactics detected",
                    evidence=evidence,
                    mitigation="Be suspicious of urgent requests, especially those requesting personal information or immediate action."
                ))
                break
        return detections

class DetectionEngine:
    """Main detection engine that coordinates all detectors with enhanced URL encoding support."""
    def __init__(self):
        self.web_attack_detector = WebAttackDetector()
        self.threat_category_detector = ThreatCategoryDetector()
        self.detection_stats = {
            'total_urls_analyzed': 0,
            'total_detections': 0,
            'urls_with_encoding': 0,
            'detections_by_type': {},
            'detections_by_severity': {}
        }
    def _has_url_encoding(self, url):
        """Check if URL contains URL encoding."""
        # Common URL encoding patterns
        encoding_patterns = [
            r'%[0-9A-Fa-f]{2}',  # Standard percent encoding
            r'\+',               # Plus encoding for spaces
        ]
        for pattern in encoding_patterns:
            if re.search(pattern, url):
                return True
        return False
    
    def analyze_url(self, url, title=None, filename=None):
        """Perform comprehensive analysis of a URL with enhanced encoding detection."""
        all_detections = []
        try:
            # Track if URL has encoding
            if self._has_url_encoding(url):
                self.detection_stats['urls_with_encoding'] += 1
                logger.debug(f"URL encoding detected in: {url[:50]}...")
            # Web attack detection
            all_detections.extend(self.web_attack_detector.detect_xss(url))
            all_detections.extend(self.web_attack_detector.detect_sqli(url))
            all_detections.extend(self.web_attack_detector.detect_csrf(url))
            
            # Threat category detection
            all_detections.extend(self.threat_category_detector.detect_phishing(url))
            all_detections.extend(self.threat_category_detector.detect_malware_download(url, filename))
            all_detections.extend(self.threat_category_detector.detect_c2_communication(url))
            all_detections.extend(self.threat_category_detector.detect_social_engineering(url, title))
            
            # Update statistics
            self.detection_stats['total_urls_analyzed'] += 1
            self.detection_stats['total_detections'] += len(all_detections)
            for detection in all_detections:
                # Count by type
                if detection.detection_type not in self.detection_stats['detections_by_type']:
                    self.detection_stats['detections_by_type'][detection.detection_type] = 0
                self.detection_stats['detections_by_type'][detection.detection_type] += 1
                # Count by severity
                if detection.severity not in self.detection_stats['detections_by_severity']:
                    self.detection_stats['detections_by_severity'][detection.severity] = 0
                self.detection_stats['detections_by_severity'][detection.severity] += 1
        except Exception as e:
            logger.error(f"Error during URL analysis: {e}")
        return all_detections
    
    def analyze_browser_artifacts(self, browser_data):
        """Analyze browser artifacts for threats with enhanced detection."""
        results = {}
        # Analyze history entries
        if 'history' in browser_data:
            history_detections = []
            # Deduplicate URLs to avoid duplicate detections from multiple visits
            unique_urls = {}
            for entry in browser_data['history']:
                url = entry.get('url', '')
                if url:
                    # Keep only the most recent visit of each URL
                    if url not in unique_urls or entry.get('visit_time', '') > unique_urls[url].get('visit_time', ''):
                        unique_urls[url] = entry
            # Process only unique URLs
            for url, entry in unique_urls.items():
                title = entry.get('title', '')
                detections = self.analyze_url(url, title)
                # Add context to detections
                for detection in detections:
                    detection.evidence.append(f"Found in browser history at {entry.get('visit_time', 'unknown time')}")
                history_detections.extend(detections)
            results['history'] = history_detections
        # Analyze download entries
        if 'downloads' in browser_data:
            download_detections = []
            for entry in browser_data['downloads']:
                source_url = entry.get('source_url', '')
                filename = entry.get('filename', '')
                detections = self.analyze_url(source_url, filename=filename)
                # Add context to detections
                for detection in detections:
                    detection.evidence.append(f"Found in downloads at {entry.get('start_time', 'unknown time')}")
                download_detections.extend(detections)
            results['downloads'] = download_detections
        return results
    
    def get_detection_summary(self):
        """Return comprehensive detection statistics."""
        high_risk_count = (self.detection_stats['detections_by_severity'].get('HIGH', 0) + 
                          self.detection_stats['detections_by_severity'].get('CRITICAL', 0))
        medium_risk_count = self.detection_stats['detections_by_severity'].get('MEDIUM', 0)
        low_risk_count = self.detection_stats['detections_by_severity'].get('LOW', 0)
        return {
            'statistics': self.detection_stats,
            'high_risk_count': high_risk_count,
            'medium_risk_count': medium_risk_count,
            'low_risk_count': low_risk_count
        }

# Factory function
def create_detection_engine():
    """Create and return a configured detection engine instance."""
    return DetectionEngine()