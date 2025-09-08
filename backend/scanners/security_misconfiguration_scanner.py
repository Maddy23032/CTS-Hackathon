import re
import requests
import asyncio
import time
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Optional

class SecurityMisconfigurationScanner:
    """Scanner for detecting security misconfigurations - GUI adapted version"""
    
    # Security headers that should be present
    SECURITY_HEADERS = {
        'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
        'X-Content-Type-Options': ['nosniff'],
        'X-XSS-Protection': ['1; mode=block', '1'],
        'Strict-Transport-Security': ['max-age='],
        'Content-Security-Policy': ['default-src'],
        'Referrer-Policy': ['strict-origin-when-cross-origin', 'no-referrer'],
        'Permissions-Policy': ['camera=', 'microphone=']
    }
    
    # Sensitive information patterns in responses
    SENSITIVE_PATTERNS = [
        r'password\s*[:=]\s*["\'][^"\']+["\']',
        r'api[_-]?key\s*[:=]\s*["\'][^"\']+["\']',
        r'secret\s*[:=]\s*["\'][^"\']+["\']',
        r'token\s*[:=]\s*["\'][^"\']+["\']',
        r'mysql_connect\(',
        r'mysqli_connect\(',
        r'PDO\(',
        r'<\?php',
        r'<%.*%>',
        r'DEBUG\s*=\s*True',
        r'RAILS_ENV\s*=\s*development'
    ]
    
    # Directory listing indicators
    DIRECTORY_LISTING_PATTERNS = [
        r'<title>Index of /',
        r'Directory listing for',
        r'<h1>Directory Listing',
        r'Parent Directory',
        r'\[DIR\]',
        r'<pre><a href="\.\.">'
    ]
    
    # Common backup/sensitive files
    SENSITIVE_FILES = [
        '/.env',
        '/.git/config',
        '/.git/HEAD',
        '/config.php',
        '/config.ini',
        '/wp-config.php',
        '/database.yml',
        '/settings.py',
        '/web.config',
        '/.htaccess',
        '/.htpasswd',
        '/robots.txt',
        '/sitemap.xml',
        '/crossdomain.xml',
        '/clientaccesspolicy.xml',
        '/backup.sql',
        '/dump.sql',
        '/phpinfo.php',
        '/info.php',
        '/test.php',
        '/admin/',
        '/administrator/',
        '/wp-admin/',
        '/phpmyadmin/',
        '/mysql/',
        '/server-status',
        '/server-info',
        '/.svn/',
        '/.bzr/',
        '/.hg/'
    ]
    
    def __init__(self, websocket_manager=None):
        self.websocket_manager = websocket_manager
        self.scan_id = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnScan Security Scanner/1.0'
        })
        
    def set_scan_id(self, scan_id: str):
        self.scan_id = scan_id
        
    async def send_websocket_message(self, message: Dict[str, Any]):
        """Send message via WebSocket if manager is available"""
        if self.websocket_manager:
            try:
                await self.websocket_manager.send_message(message)
            except Exception as e:
                print(f"WebSocket send error: {e}")
                
    def log(self, message, level="INFO"):
        """Log message with WebSocket support"""
        print(f"[{level}] {message}")
        
        if self.websocket_manager:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(self.send_websocket_message({
                        "type": "log",
                        "level": level.lower(),
                        "message": message,
                        "timestamp": time.time(),
                        "scan_id": self.scan_id,
                        "phase": "security_misconfiguration"
                    }))
            except Exception as e:
                print(f"Logging error: {e}")

    async def scan(self, attack_surface: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Main scanning method"""
        findings = []
        
        # Get unique base URLs from attack surface
        base_urls = set()
        for url, _ in attack_surface.get('urls', []):
            # Extract base URL (protocol + domain)
            if '://' in url:
                base_url = '/'.join(url.split('/')[:3])
                base_urls.add(base_url)
        
        for base_url in base_urls:
            self.log(f"Scanning {base_url} for security misconfigurations...")
            
            # Check security headers
            findings.extend(await self._check_security_headers(base_url))
            
            # Check for directory listing
            findings.extend(await self._check_directory_listing(base_url))
            
            # Check for sensitive files
            findings.extend(await self._check_sensitive_files(base_url))
            
            # Check for information disclosure
            findings.extend(await self._check_information_disclosure(base_url))
            
            await asyncio.sleep(0.1)  # Rate limiting
        
        return findings

    async def _check_security_headers(self, base_url: str) -> List[Dict[str, Any]]:
        """Check for missing or misconfigured security headers"""
        findings = []
        
        try:
            self.log(f"Checking security headers for {base_url}")
            response = self.session.get(base_url, timeout=10, allow_redirects=True)
            
            for header_name, expected_values in self.SECURITY_HEADERS.items():
                if header_name not in response.headers:
                    findings.append({
                        'type': 'Security Misconfiguration',
                        'severity': 'Medium',
                        'url': base_url,
                        'parameter': header_name,
                        'payload': f'Missing {header_name} header',
                        'evidence': f'Security header {header_name} is not present',
                        'remediation': f'Add {header_name} header with appropriate value',
                        'confidence': 'High'
                    })
                    self.log(f"Missing security header: {header_name}", "WARNING")
                else:
                    # Check if header value is properly configured
                    header_value = response.headers[header_name]
                    is_properly_configured = any(expected in header_value for expected in expected_values)
                    
                    if not is_properly_configured:
                        findings.append({
                            'type': 'Security Misconfiguration',
                            'severity': 'Low',
                            'url': base_url,
                            'parameter': header_name,
                            'payload': header_value,
                            'evidence': f'Security header {header_name} may be misconfigured: {header_value}',
                            'remediation': f'Review {header_name} header configuration',
                            'confidence': 'Medium'
                        })
                        self.log(f"Potentially misconfigured header: {header_name} = {header_value}", "INFO")
                        
        except Exception as e:
            self.log(f"Error checking security headers for {base_url}: {e}", "ERROR")
            
        return findings

    async def _check_directory_listing(self, base_url: str) -> List[Dict[str, Any]]:
        """Check for directory listing vulnerabilities"""
        findings = []
        common_dirs = ['/', '/images/', '/css/', '/js/', '/uploads/', '/files/', '/admin/']
        
        for directory in common_dirs:
            try:
                url = urljoin(base_url, directory)
                self.log(f"Checking directory listing: {url}")
                
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    for pattern in self.DIRECTORY_LISTING_PATTERNS:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            findings.append({
                                'type': 'Security Misconfiguration',
                                'severity': 'Medium',
                                'url': url,
                                'parameter': 'Directory Listing',
                                'payload': directory,
                                'evidence': f'Directory listing enabled at {url}',
                                'remediation': 'Disable directory listing in web server configuration',
                                'confidence': 'High'
                            })
                            self.log(f"Directory listing found at: {url}", "WARNING")
                            break
                            
            except Exception as e:
                self.log(f"Error checking directory listing for {directory}: {e}", "ERROR")
                
            await asyncio.sleep(0.1)  # Rate limiting
                
        return findings

    async def _check_sensitive_files(self, base_url: str) -> List[Dict[str, Any]]:
        """Check for accessible sensitive files"""
        findings = []
        
        for file_path in self.SENSITIVE_FILES:
            try:
                url = urljoin(base_url, file_path)
                self.log(f"Checking sensitive file: {url}")
                
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200 and len(response.text) > 10:
                    # Additional checks for specific file types
                    is_sensitive = True
                    
                    if file_path.endswith('.txt') and 'robots.txt' in file_path:
                        # robots.txt is expected, but check for sensitive information
                        if any(keyword in response.text.lower() for keyword in ['admin', 'private', 'secret', 'backup']):
                            is_sensitive = True
                        else:
                            is_sensitive = False
                    
                    if is_sensitive:
                        findings.append({
                            'type': 'Security Misconfiguration',
                            'severity': 'High' if any(ext in file_path for ext in ['.env', '.git', 'config']) else 'Medium',
                            'url': url,
                            'parameter': 'Sensitive File Access',
                            'payload': file_path,
                            'evidence': f'Sensitive file accessible: {url} (Content length: {len(response.text)})',
                            'remediation': f'Restrict access to {file_path} or remove if not needed',
                            'confidence': 'High'
                        })
                        self.log(f"Sensitive file accessible: {url}", "WARNING")
                        
            except Exception as e:
                # Expected for most files - they should not be accessible
                pass
                
            await asyncio.sleep(0.1)  # Rate limiting
                
        return findings

    async def _check_information_disclosure(self, base_url: str) -> List[Dict[str, Any]]:
        """Check for information disclosure in responses"""
        findings = []
        
        try:
            self.log(f"Checking for information disclosure: {base_url}")
            response = self.session.get(base_url, timeout=10)
            
            for pattern in self.SENSITIVE_PATTERNS:
                matches = re.finditer(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    # Mask sensitive information in evidence
                    evidence_text = match.group()[:50] + "..." if len(match.group()) > 50 else match.group()
                    
                    findings.append({
                        'type': 'Security Misconfiguration',
                        'severity': 'High',
                        'url': base_url,
                        'parameter': 'Information Disclosure',
                        'payload': pattern,
                        'evidence': f'Sensitive information pattern found: {evidence_text}',
                        'remediation': 'Remove sensitive information from public responses',
                        'confidence': 'Medium'
                    })
                    self.log(f"Information disclosure found: {pattern}", "WARNING")
                    
        except Exception as e:
            self.log(f"Error checking information disclosure for {base_url}: {e}", "ERROR")
            
        return findings
