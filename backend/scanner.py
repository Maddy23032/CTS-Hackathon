import requests
from typing import List, Dict, Any
from urllib.parse import urljoin
import os
import json


class VulnerabilityScanner:
    """Lightweight base scanner providing shared state and helpers."""

    def __init__(self, target_url: str, scan_types: List[str], verbose: bool = False, delay: float = 0.1):
        self.target_url = target_url
        self.scan_types = [s.lower() for s in (scan_types or [])]
        self.verbose = verbose
        self.delay = delay

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "VulnScan/1.0 (Automated Security Scanner)"
        })

        # Shared state across scanners
        self.discovered_urls = set([target_url])
        self.forms: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []

        # Payload loading logic
        scan_mode = os.getenv("SCAN_MODE", "full")  # can be set externally
        # XSS
        xss_path = os.path.join(os.path.dirname(__file__), "payloads", "xss_payloads.txt")
        try:
            with open(xss_path, "r", encoding="utf-8") as f:
                self.xss_payloads = [line.strip() for line in f if line.strip()]
        except Exception:
            self.xss_payloads = [
                "<script>alert(1)</script>",
                "\"'><svg/onload=alert(1)>",
                "<img src=x onerror=alert(1)>",
            ]
        if scan_mode == "fast":
            self.xss_payloads = self.xss_payloads[:10]
        # SQLi
        sqli_path = os.path.join(os.path.dirname(__file__), "payloads", "sqli_payloads.json")
        sqli_payloads = []
        try:
            with open(sqli_path, "r", encoding="utf-8") as f:
                db_templates = json.load(f)
                for db_type, payloads in db_templates.items():
                    sqli_payloads.extend(payloads)
        except Exception:
            sqli_payloads = [
                "' OR '1'='1 -- ",
                "\" OR \"1\"=\"1\" -- ",
                "admin' -- ",
            ]
        if scan_mode == "fast":
            sqli_payloads = sqli_payloads[:10]
        self.sqli_payloads = sqli_payloads

    def log(self, msg: str):
        if self.verbose:
            print(f"[Scanner] {msg}")

    def extract_form_data(self, form, page_url: str) -> Dict[str, Any]:
        """Extract basic form data from a BeautifulSoup form tag."""
        try:
            action = form.get("action") or page_url
            method = (form.get("method") or "get").lower()
            form_url = urljoin(page_url, action)
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs.append(name)
            return {
                "action": form_url,
                "method": method,
                "inputs": inputs,
            }
        except Exception:
            return {
                "action": page_url,
                "method": "get",
                "inputs": [],
            }

    # Naive vulnerability heuristics
    def is_xss_vulnerable(self, payload: str, html: str) -> bool:
        try:
            return payload.lower() in (html or "").lower()
        except Exception:
            return False

    def extract_xss_evidence(self, payload: str, html: str) -> str:
        return f"Payload reflected in response: {payload[:40]}"

    def is_sqli_vulnerable(self, response) -> bool:
        indicators = [
            "sql syntax", "mysql", "mysqli", "postgres", "sqlserver",
            "sqlite", "you have an error in your sql syntax", "ora-",
        ]
        try:
            text = (response.text or "").lower()
        except Exception:
            return False
        return any(ind in text for ind in indicators) or response.status_code >= 500

    def extract_sqli_evidence(self, text: str) -> str:
        return "Database error signature detected in response"
import requests
import re
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import time

class VulnerabilityScanner:
    def __init__(self, target_url, scan_types, verbose=False, delay=0.1):
        self.target_url = target_url
        self.scan_types = scan_types
        self.verbose = verbose
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnScan-Scanner/1.0'
        })
        self.discovered_urls = set()
        self.forms = []
        self.vulnerabilities = []
        
        # XSS Payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'\"><script>alert(1)</script>",
            "<iframe src=javascript:alert(1)></iframe>"
        ]
        
        # SQLi Payloads
        self.sqli_payloads = [
            "' OR '1'='1' --",
            "'; DROP TABLE users; --",
            "' UNION SELECT version() --",
            "1' OR '1'='1",
            "admin'--",
            "' OR 1=1#"
        ]

    def log(self, message, level="INFO"):
        if self.verbose:
            print(f"[{level}] {message}")

    async def crawl_website(self, max_depth=2):
        """Crawl the website to discover URLs and forms"""
        self.log("Starting website crawling...")
        
        urls_to_visit = [(self.target_url, 0)]
        visited = set()
        
        while urls_to_visit:
            url, depth = urls_to_visit.pop(0)
            
            if url in visited or depth > max_depth:
                continue
                
            visited.add(url)
            self.discovered_urls.add(url)
            
            self.log(f"Crawling: {url} (depth {depth})")
            
            try:
                response = self.session.get(url, timeout=10)
                await asyncio.sleep(self.delay)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(url, href)
                        
                        # Only crawl same domain
                        if urlparse(full_url).netloc == urlparse(self.target_url).netloc:
                            if full_url not in visited and depth < max_depth:
                                urls_to_visit.append((full_url, depth + 1))
                    
                    # Find all forms
                    for form in soup.find_all('form'):
                        form_data = self.extract_form_data(form, url)
                        if form_data:
                            self.forms.append(form_data)
                            self.log(f"Found form: {form_data['action']} ({form_data['method']})")
                            
            except Exception as e:
                self.log(f"Error crawling {url}: {str(e)}", "ERROR")
        
        self.log(f"Crawling completed. Found {len(self.discovered_urls)} URLs and {len(self.forms)} forms")

    def extract_form_data(self, form, base_url):
        """Extract form data for testing"""
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        action_url = urljoin(base_url, action)
        
        inputs = []
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            name = input_tag.get('name')
            if name:
                inputs.append(name)
        
        return {
            'action': action_url,
            'method': method,
            'inputs': inputs,
            'base_url': base_url
        }

    async def scan_xss(self):
        """Scan for XSS vulnerabilities"""
        if 'xss' not in self.scan_types:
            return
            
        self.log("Starting XSS vulnerability scan...")
        
        # Test forms for XSS
        for form in self.forms:
            for input_name in form['inputs']:
                for payload in self.xss_payloads:
                    self.log(f"Testing XSS payload: {payload} in form {form['action']}")
                    
                    # Prepare form data
                    data = {inp: payload if inp == input_name else 'test' for inp in form['inputs']}
                    
                    try:
                        if form['method'] == 'post':
                            response = self.session.post(form['action'], data=data, timeout=10)
                        else:
                            response = self.session.get(form['action'], params=data, timeout=10)
                        
                        await asyncio.sleep(self.delay)
                        
                        if self.is_xss_vulnerable(payload, response.text):
                            vuln = {
                                'type': 'XSS',
                                'url': form['action'],
                                'parameter': input_name,
                                'payload': payload,
                                'evidence': self.extract_xss_evidence(payload, response.text),
                                'method': form['method']
                            }
                            self.vulnerabilities.append(vuln)
                            self.log(f"XSS vulnerability found: {form['action']} parameter={input_name}", "VULN")
                            break  # Found one, move to next parameter
                            
                    except Exception as e:
                        self.log(f"Error testing XSS on {form['action']}: {str(e)}", "ERROR")
        
        # Test URLs with parameters for XSS
        for url in self.discovered_urls:
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param_name in params.keys():
                    for payload in self.xss_payloads:
                        self.log(f"Testing XSS payload: {payload} in URL parameter {param_name}")
                        
                        test_params = {p: payload if p == param_name else 'test' for p in params.keys()}
                        
                        try:
                            response = self.session.get(f"{parsed.scheme}://{parsed.netloc}{parsed.path}", params=test_params, timeout=10)
                            await asyncio.sleep(self.delay)
                            
                            if self.is_xss_vulnerable(payload, response.text):
                                vuln = {
                                    'type': 'XSS',
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'evidence': self.extract_xss_evidence(payload, response.text),
                                    'method': 'GET'
                                }
                                self.vulnerabilities.append(vuln)
                                self.log(f"XSS vulnerability found: {url} parameter={param_name}", "VULN")
                                break
                                
                        except Exception as e:
                            self.log(f"Error testing XSS on {url}: {str(e)}", "ERROR")

    async def scan_sqli(self):
        """Scan for SQL injection vulnerabilities"""
        if 'sqli' not in self.scan_types:
            return
            
        self.log("Starting SQL injection vulnerability scan...")
        
        # Test forms for SQLi
        for form in self.forms:
            for input_name in form['inputs']:
                for payload in self.sqli_payloads:
                    self.log(f"Testing SQLi payload: {payload} in form {form['action']}")
                    
                    data = {inp: payload if inp == input_name else 'test' for inp in form['inputs']}
                    
                    try:
                        if form['method'] == 'post':
                            response = self.session.post(form['action'], data=data, timeout=10)
                        else:
                            response = self.session.get(form['action'], params=data, timeout=10)
                        
                        await asyncio.sleep(self.delay)
                        
                        if self.is_sqli_vulnerable(response):
                            vuln = {
                                'type': 'SQLi',
                                'url': form['action'],
                                'parameter': input_name,
                                'payload': payload,
                                'evidence': self.extract_sqli_evidence(response.text),
                                'method': form['method']
                            }
                            self.vulnerabilities.append(vuln)
                            self.log(f"SQL injection vulnerability found: {form['action']} parameter={input_name}", "VULN")
                            break
                            
                    except Exception as e:
                        self.log(f"Error testing SQLi on {form['action']}: {str(e)}", "ERROR")

    def is_xss_vulnerable(self, payload, response_text):
        """Check if XSS payload is reflected in response"""
        # Simple reflection check
        if payload in response_text:
            return True
        
        # Check for various encoding bypasses
        encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
        if encoded_payload in response_text:
            return True
            
        return False

    def extract_xss_evidence(self, payload, response_text):
        """Extract evidence of XSS vulnerability"""
        start = response_text.find(payload)
        if start != -1:
            # Return 100 characters around the payload
            evidence_start = max(0, start - 50)
            evidence_end = min(len(response_text), start + len(payload) + 50)
            return response_text[evidence_start:evidence_end]
        return "Payload reflected in response"

    def is_sqli_vulnerable(self, response):
        """Check for SQL injection indicators"""
        sql_errors = [
            "mysql_fetch_array",
            "ORA-00933",
            "Microsoft OLE DB Provider",
            "SQLServerException",
            "PostgreSQL query failed",
            "mysql_num_rows",
            "Warning: mysql",
            "MySQLSyntaxErrorException",
            "valid MySQL result",
            "check the manual that corresponds to your MySQL",
            "SQLSTATE"
        ]
        
        response_text = response.text.lower()
        for error in sql_errors:
            if error.lower() in response_text:
                return True
        return False

    def extract_sqli_evidence(self, response_text):
        """Extract evidence of SQL injection"""
        # Look for common SQL error patterns
        sql_patterns = [
            r"mysql_fetch_array.*",
            r"Warning: mysql.*",
            r"SQLSTATE\[.*\]",
            r"ORA-\d+.*",
            r"Microsoft.*OLE DB.*"
        ]
        
        for pattern in sql_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)[:200]  # First 200 chars
        
        return "SQL error detected in response"

    async def run_scan(self):
        """Run the complete vulnerability scan"""
        self.log(f"Starting vulnerability scan for: {self.target_url}")
        self.log(f"Scan types: {', '.join(self.scan_types)}")
        
        # Phase 1: Crawling
        await self.crawl_website()
        
        # Phase 2: Vulnerability Testing
        if 'xss' in self.scan_types:
            await self.scan_xss()
        
        if 'sqli' in self.scan_types:
            await self.scan_sqli()
        
        self.log(f"Scan completed. Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities
