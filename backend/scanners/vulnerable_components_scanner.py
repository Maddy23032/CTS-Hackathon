import re
import requests
import asyncio
import time
import json
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Optional

class VulnerableComponentsScanner:
    """Scanner for detecting vulnerable and outdated components - GUI adapted version"""
    
    # Known vulnerable software signatures
    VULNERABLE_SIGNATURES = {
        # Web servers
        'apache': {
            'patterns': [r'Apache/(\d+\.\d+\.\d+)', r'Server:\s*Apache/(\d+\.\d+\.\d+)'],
            'vulnerable_versions': ['2.4.29', '2.4.28', '2.4.27', '2.4.26', '2.4.25', '2.2.34']
        },
        'nginx': {
            'patterns': [r'nginx/(\d+\.\d+\.\d+)', r'Server:\s*nginx/(\d+\.\d+\.\d+)'],
            'vulnerable_versions': ['1.10.3', '1.12.2', '1.13.12', '1.14.2', '1.15.12']
        },
        'iis': {
            'patterns': [r'Microsoft-IIS/(\d+\.\d+)', r'Server:\s*Microsoft-IIS/(\d+\.\d+)'],
            'vulnerable_versions': ['7.0', '7.5', '8.0', '8.5']
        },
        
        # Frameworks and CMS
        'wordpress': {
            'patterns': [r'wp-content', r'wordpress', r'/wp-admin/', r'/wp-includes/'],
            'version_patterns': [r'wp-includes/js/jquery/jquery\.js\?ver=(\d+\.\d+\.\d+)', r'generator.*WordPress\s+(\d+\.\d+\.\d+)'],
            'vulnerable_versions': ['4.9.8', '5.0.3', '5.1.1', '5.2.4', '5.8.0', '5.9.1']
        },
        'drupal': {
            'patterns': [r'/sites/default/', r'/modules/', r'Drupal'],
            'version_patterns': [r'Drupal (\d+\.\d+)', r'generator.*Drupal\s+(\d+\.\d+)'],
            'vulnerable_versions': ['7.59', '8.5.8', '8.6.2', '9.0.0', '9.1.0']
        },
        'joomla': {
            'patterns': [r'/administrator/', r'joomla', r'/components/'],
            'version_patterns': [r'Joomla! (\d+\.\d+\.\d+)', r'generator.*Joomla!\s+(\d+\.\d+\.\d+)'],
            'vulnerable_versions': ['3.8.13', '3.9.1', '3.9.12', '4.0.0', '4.1.0']
        },
        
        # JavaScript libraries
        'jquery': {
            'patterns': [r'jquery-(\d+\.\d+\.\d+)\.min\.js', r'jquery\.js\?ver=(\d+\.\d+\.\d+)'],
            'vulnerable_versions': ['1.6.2', '1.7.2', '1.8.3', '1.9.1', '2.1.4', '3.0.0', '3.4.1']
        },
        'angular': {
            'patterns': [r'angular\.min\.js', r'angular-(\d+\.\d+\.\d+)'],
            'version_patterns': [r'angular\.version\s*=\s*["\'](\d+\.\d+\.\d+)["\']'],
            'vulnerable_versions': ['1.2.0', '1.3.0', '1.4.0', '1.5.0', '1.6.0']
        },
        'react': {
            'patterns': [r'react\.min\.js', r'react-(\d+\.\d+\.\d+)'],
            'version_patterns': [r'React\s+v(\d+\.\d+\.\d+)'],
            'vulnerable_versions': ['16.0.0', '16.8.0', '17.0.0']
        },
        
        # PHP frameworks
        'laravel': {
            'patterns': [r'laravel_session', r'/vendor/laravel/', r'Laravel'],
            'version_patterns': [r'Laravel\s+v(\d+\.\d+\.\d+)'],
            'vulnerable_versions': ['5.5.40', '5.6.0', '5.7.0', '5.8.0', '6.0.0']
        },
        'symfony': {
            'patterns': [r'/bundles/', r'Symfony', r'_sf2_'],
            'version_patterns': [r'Symfony\s+(\d+\.\d+\.\d+)'],
            'vulnerable_versions': ['3.4.0', '4.0.0', '4.1.0', '4.2.0', '5.0.0']
        }
    }
    
    # Common vulnerable component endpoints
    COMPONENT_ENDPOINTS = [
        '/js/jquery.min.js',
        '/js/angular.min.js',
        '/js/react.min.js',
        '/css/bootstrap.min.css',
        '/vendor/phpunit/',
        '/vendor/composer/',
        '/node_modules/',
        '/.well-known/',
        '/api/version',
        '/version',
        '/about',
        '/readme.txt',
        '/changelog.txt',
        '/package.json',
        '/composer.json',
        '/bower.json'
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
                        "phase": "vulnerable_components"
                    }))
            except Exception as e:
                print(f"Logging error: {e}")

    async def scan(self, attack_surface: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Main scanning method"""
        findings = []
        
        # Get URLs from attack surface
        urls_to_scan = set()
        for url, _ in attack_surface.get('urls', []):
            urls_to_scan.add(url)
            
        # Also add base URLs
        base_urls = set()
        for url in urls_to_scan:
            if '://' in url:
                base_url = '/'.join(url.split('/')[:3])
                base_urls.add(base_url)
        
        for base_url in base_urls:
            self.log(f"Scanning {base_url} for vulnerable components...")
            
            # Check server headers for version information
            findings.extend(await self._check_server_headers(base_url))
            
            # Check for component endpoints
            findings.extend(await self._check_component_endpoints(base_url))
            
            # Check page content for component signatures
            findings.extend(await self._check_page_content(base_url))
            
            await asyncio.sleep(0.1)  # Rate limiting
        
        return findings

    async def _check_server_headers(self, base_url: str) -> List[Dict[str, Any]]:
        """Check server headers for version information"""
        findings = []
        
        try:
            self.log(f"Checking server headers for {base_url}")
            response = self.session.get(base_url, timeout=10, allow_redirects=True)
            
            # Check Server header
            server_header = response.headers.get('Server', '')
            if server_header:
                findings.extend(await self._analyze_component_version('Server Header', server_header, base_url))
            
            # Check X-Powered-By header
            powered_by = response.headers.get('X-Powered-By', '')
            if powered_by:
                findings.extend(await self._analyze_component_version('X-Powered-By', powered_by, base_url))
                
            # Check other technology headers
            tech_headers = ['X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Generator', 'X-Drupal-Cache']
            for header in tech_headers:
                if header in response.headers:
                    findings.extend(await self._analyze_component_version(header, response.headers[header], base_url))
                    
        except Exception as e:
            self.log(f"Error checking server headers for {base_url}: {e}", "ERROR")
            
        return findings

    async def _check_component_endpoints(self, base_url: str) -> List[Dict[str, Any]]:
        """Check common component endpoints"""
        findings = []
        
        for endpoint in self.COMPONENT_ENDPOINTS:
            try:
                url = urljoin(base_url, endpoint)
                self.log(f"Checking component endpoint: {url}")
                
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    # Analyze the content for version information
                    findings.extend(await self._analyze_component_content(url, response.text, response.headers))
                    
            except Exception as e:
                # Expected for most endpoints - they may not exist
                pass
                
            await asyncio.sleep(0.1)  # Rate limiting
                
        return findings

    async def _check_page_content(self, base_url: str) -> List[Dict[str, Any]]:
        """Check page content for component signatures"""
        findings = []
        
        try:
            self.log(f"Checking page content for components: {base_url}")
            response = self.session.get(base_url, timeout=10)
            
            if response.status_code == 200:
                findings.extend(await self._analyze_component_content(base_url, response.text, response.headers))
                
        except Exception as e:
            self.log(f"Error checking page content for {base_url}: {e}", "ERROR")
            
        return findings

    async def _analyze_component_version(self, source: str, content: str, url: str) -> List[Dict[str, Any]]:
        """Analyze content for component versions"""
        findings = []
        
        for component_name, component_info in self.VULNERABLE_SIGNATURES.items():
            # Check general patterns first
            for pattern in component_info.get('patterns', []):
                if re.search(pattern, content, re.IGNORECASE):
                    self.log(f"Found {component_name} signature in {source}")
                    
                    # Try to extract version if version patterns exist
                    version = None
                    for version_pattern in component_info.get('version_patterns', []):
                        version_match = re.search(version_pattern, content, re.IGNORECASE)
                        if version_match:
                            version = version_match.group(1)
                            break
                    
                    # Check if version is vulnerable
                    if version and version in component_info.get('vulnerable_versions', []):
                        findings.append({
                            'type': 'Vulnerable Components',
                            'severity': 'High',
                            'url': url,
                            'parameter': component_name,
                            'payload': version,
                            'evidence': f'Vulnerable {component_name} version {version} detected in {source}',
                            'remediation': f'Update {component_name} to the latest secure version',
                            'confidence': 'High'
                        })
                        self.log(f"Vulnerable {component_name} v{version} found!", "WARNING")
                    elif version:
                        # Version found but need to check if it's outdated (basic check)
                        findings.append({
                            'type': 'Vulnerable Components',
                            'severity': 'Medium',
                            'url': url,
                            'parameter': component_name,
                            'payload': version,
                            'evidence': f'{component_name} version {version} detected in {source} - verify if current',
                            'remediation': f'Verify {component_name} version {version} is up to date',
                            'confidence': 'Medium'
                        })
                        self.log(f"{component_name} v{version} detected - verify currency", "INFO")
                    else:
                        # Component detected but no version
                        findings.append({
                            'type': 'Vulnerable Components',
                            'severity': 'Low',
                            'url': url,
                            'parameter': component_name,
                            'payload': 'Version unknown',
                            'evidence': f'{component_name} detected in {source} but version could not be determined',
                            'remediation': f'Verify {component_name} version and update if necessary',
                            'confidence': 'Low'
                        })
                        self.log(f"{component_name} detected but version unknown", "INFO")
                    
                    break  # Found this component, no need to check other patterns
                    
        return findings

    async def _analyze_component_content(self, url: str, content: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Analyze content and headers for component information"""
        findings = []
        
        # Check content for component signatures
        findings.extend(await self._analyze_component_version('Page Content', content, url))
        
        # Check specific file types
        if url.endswith('.js'):
            findings.extend(await self._analyze_javascript_content(url, content))
        elif url.endswith('.css'):
            findings.extend(await self._analyze_css_content(url, content))
        elif url.endswith('.json'):
            findings.extend(await self._analyze_json_content(url, content))
            
        # Check meta tags in HTML content
        meta_matches = re.finditer(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', content, re.IGNORECASE)
        for match in meta_matches:
            generator_content = match.group(1)
            findings.extend(await self._analyze_component_version('Meta Generator', generator_content, url))
            
        return findings

    async def _analyze_javascript_content(self, url: str, content: str) -> List[Dict[str, Any]]:
        """Analyze JavaScript files for version information"""
        findings = []
        
        # Look for version comments or variables
        version_patterns = [
            r'/\*!?\s*([^*]+)\s+v?(\d+\.\d+\.\d+)',
            r'version\s*:\s*["\'](\d+\.\d+\.\d+)["\']',
            r'VERSION\s*=\s*["\'](\d+\.\d+\.\d+)["\']',
            r'@version\s+(\d+\.\d+\.\d+)'
        ]
        
        for pattern in version_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match.groups()) >= 2:
                    component = match.group(1).strip()
                    version = match.group(2) if len(match.groups()) >= 2 else match.group(1)
                else:
                    component = "JavaScript Library"
                    version = match.group(1)
                    
                findings.append({
                    'type': 'Vulnerable Components',
                    'severity': 'Low',
                    'url': url,
                    'parameter': component,
                    'payload': version,
                    'evidence': f'JavaScript component {component} version {version} found',
                    'remediation': f'Verify {component} version {version} is secure and up to date',
                    'confidence': 'Medium'
                })
                
        return findings

    async def _analyze_css_content(self, url: str, content: str) -> List[Dict[str, Any]]:
        """Analyze CSS files for version information"""
        findings = []
        
        # Look for version comments in CSS
        version_pattern = r'/\*!?\s*([^*]+)\s+v?(\d+\.\d+\.\d+)'
        matches = re.finditer(version_pattern, content, re.IGNORECASE)
        
        for match in matches:
            component = match.group(1).strip()
            version = match.group(2)
            
            findings.append({
                'type': 'Vulnerable Components',
                'severity': 'Low',
                'url': url,
                'parameter': component,
                'payload': version,
                'evidence': f'CSS framework {component} version {version} found',
                'remediation': f'Verify {component} version {version} is secure and up to date',
                'confidence': 'Medium'
            })
            
        return findings

    async def _analyze_json_content(self, url: str, content: str) -> List[Dict[str, Any]]:
        """Analyze JSON files (package.json, etc.) for version information"""
        findings = []
        
        try:
            json_data = json.loads(content)
            
            # Check package.json structure
            if 'name' in json_data and 'version' in json_data:
                component = json_data['name']
                version = json_data['version']
                
                findings.append({
                    'type': 'Vulnerable Components',
                    'severity': 'Medium',
                    'url': url,
                    'parameter': component,
                    'payload': version,
                    'evidence': f'Package {component} version {version} exposed in {url}',
                    'remediation': f'Remove public access to package.json or verify {component} is secure',
                    'confidence': 'High'
                })
                
            # Check dependencies
            for dep_section in ['dependencies', 'devDependencies']:
                if dep_section in json_data:
                    for dep_name, dep_version in json_data[dep_section].items():
                        findings.append({
                            'type': 'Vulnerable Components',
                            'severity': 'Low',
                            'url': url,
                            'parameter': dep_name,
                            'payload': dep_version,
                            'evidence': f'Dependency {dep_name} version {dep_version} exposed',
                            'remediation': f'Remove public access to package.json and verify dependencies are secure',
                            'confidence': 'Medium'
                        })
                        
        except json.JSONDecodeError:
            pass  # Not valid JSON
            
        return findings
