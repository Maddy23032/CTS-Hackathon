import asyncio
from scanner import VulnerabilityScanner
from typing import Dict, List, Any, Optional
import json
import time

# Import the new scanners
from scanners.security_misconfiguration_scanner import SecurityMisconfigurationScanner
from scanners.vulnerable_components_scanner import VulnerableComponentsScanner
from scanners.ssrf_scanner import SSRFScanner
from oast_collaborator import oast_collaborator
from scanners.csrf_scanner import CSRFScanner
from scanners.broken_access_control_scanner import BrokenAccessControlScanner
from scanners.cryptographic_failures_scanner import CryptographicFailuresScanner
from scanners.auth_failures_scanner import AuthenticationFailuresScanner
from scanners.integrity_failures_scanner import IntegrityFailuresScanner
from scanners.logging_monitoring_failures_scanner import LoggingMonitoringFailuresScanner


class RealTimeScanner(VulnerabilityScanner):
    def __init__(self, target_url, scan_types, verbose=False, delay=0.1, websocket_manager=None, log_callback=None, enable_oast: bool=False, headless: bool=False):
        super().__init__(target_url, scan_types, verbose, delay)
        self.websocket_manager = websocket_manager
        self.log_callback = log_callback
        self.scan_id: Optional[str] = None
        self.current_url = ""
        self.current_payload = ""
        self._cancel = False
        self.enable_oast = enable_oast
        self.oast = oast_collaborator if enable_oast else None
        self.headless = headless
        self._headless_failed = False

        # Initialize specialized scanners
        self.security_misconfiguration_scanner = SecurityMisconfigurationScanner(websocket_manager)
        self.vulnerable_components_scanner = VulnerableComponentsScanner(websocket_manager)
        self.ssrf_scanner = SSRFScanner(websocket_manager)
        # New heuristic scanners (reuse shared session where possible via to_thread style wrappers later)
        try:
            self.bac_scanner = BrokenAccessControlScanner(self.session, verbose=self.verbose)
        except Exception:
            self.bac_scanner = None
        try:
            self.crypto_scanner = CryptographicFailuresScanner(self.session, verbose=self.verbose)
        except Exception:
            self.crypto_scanner = None
        try:
            self.auth_scanner = AuthenticationFailuresScanner(self.session, verbose=self.verbose)
        except Exception:
            self.auth_scanner = None
        try:
            self.integrity_scanner = IntegrityFailuresScanner(self.session, verbose=self.verbose)
        except Exception:
            self.integrity_scanner = None
        try:
            self.logmon_scanner = LoggingMonitoringFailuresScanner(self.session, verbose=self.verbose)
        except Exception:
            self.logmon_scanner = None
        # Legacy synchronous CSRF scanner wrapped via to_thread
        try:
            self.csrf_scanner = CSRFScanner(self.session, verbose=self.verbose)
        except Exception:
            self.csrf_scanner = None

    def set_scan_id(self, scan_id: str):
        self.scan_id = scan_id
        # Set scan ID for specialized scanners
        self.security_misconfiguration_scanner.set_scan_id(scan_id)
        self.vulnerable_components_scanner.set_scan_id(scan_id)
        self.ssrf_scanner.set_scan_id(scan_id)

    def cancel(self):
        """Request cooperative cancellation of the running scan."""
        self._cancel = True
        # Propagate to sub-scanners if they implement cancel
        for s in (
            self.security_misconfiguration_scanner,
            self.vulnerable_components_scanner,
            self.ssrf_scanner,
        ):
            try:
                if hasattr(s, "cancel") and callable(getattr(s, "cancel")):
                    s.cancel()
            except Exception:
                pass

    async def send_websocket_message(self, message: Dict[str, Any]):
        """Send message via WebSocket if manager is available"""
        if self.websocket_manager:
            try:
                await self.websocket_manager.send_message(message)
            except Exception as e:
                print(f"WebSocket send error: {e}")

    def log(self, message, level="INFO"):
        """Override log method to use a callback for centralized logging."""
        if self.verbose:
            print(f"[{level}] {message}")
        if self.log_callback:
            try:
                self.log_callback(message=message, level=level.lower(), scan_id=self.scan_id)
            except Exception as e:
                print(f"Error in log_callback: {e}")

    async def crawl_website(self, max_depth=2):
        """Enhanced crawl with optional headless (Playwright) enrichment."""
        from urllib.parse import urljoin, urlparse
        from bs4 import BeautifulSoup

        self.log("Starting website crawling...")
        if self._cancel:
            return

        await self.send_websocket_message({
            "type": "phase_update",
            "phase": "crawling",
            "progress": 10,
        })

        urls_to_visit: List[tuple[str, int]] = [(self.target_url, 0)]
        visited: set[str] = set()

        while urls_to_visit:
            if self._cancel:
                self.log("Cancellation requested during crawl. Stopping crawl.", "INFO")
                break

            url, depth = urls_to_visit.pop(0)
            if url in visited or depth > max_depth:
                continue

            visited.add(url)
            self.discovered_urls.add(url)
            self.current_url = url

            self.log(f"Crawling: {url} (depth {depth})")
            await self.send_websocket_message({
                "type": "url_crawled",
                "url": url,
                "depth": depth,
                "total_urls": len(self.discovered_urls),
            })

            try:
                response = self.session.get(url, timeout=10)
                await asyncio.sleep(self.delay)
                page_html = response.text if getattr(response, 'status_code', 0) == 200 else ""

                dynamic_links: List[str] = []
                dynamic_forms: List[Dict[str, Any]] = []

                # Optional headless enrichment for dynamic content
                if self.headless and not self._cancel:
                    try:
                        async def run_playwright(u: str):
                            def _render():
                                try:
                                    from playwright.sync_api import sync_playwright
                                except Exception:
                                    raise RuntimeError("playwright not installed")
                                collected_links: List[str] = []
                                collected_forms: List[Dict[str, Any]] = []
                                html_content = ""
                                with sync_playwright() as p:
                                    browser = p.chromium.launch(headless=True)
                                    page = browser.new_page()
                                    page.goto(u, timeout=15000, wait_until='networkidle')
                                    page.wait_for_timeout(800)
                                    html_content = page.content()
                                    for a in page.query_selector_all('a[href]'):
                                        href = a.get_attribute('href')
                                        if href:
                                            collected_links.append(urljoin(u, href))
                                    for f in page.query_selector_all('form'):
                                        action = f.get_attribute('action') or u
                                        method = (f.get_attribute('method') or 'get').lower()
                                        inputs = []
                                        for inp in f.query_selector_all('input,textarea,select'):
                                            name = inp.get_attribute('name')
                                            if name:
                                                inputs.append(name)
                                        collected_forms.append({
                                            'action': urljoin(u, action),
                                            'method': method,
                                            'inputs': inputs
                                        })
                                    browser.close()
                                return html_content, collected_links, collected_forms
                            return await asyncio.to_thread(_render)
                        html_rendered, dynamic_links, dynamic_forms = await run_playwright(url)
                        if len(html_rendered) > len(page_html):
                            page_html = html_rendered
                    except Exception as he:
                        if not self._headless_failed:
                            self.log(f"Headless enrichment disabled: {he}", "WARNING")
                        self._headless_failed = True

                if page_html:
                    soup = BeautifulSoup(page_html, "html.parser")
                    for link in soup.find_all("a", href=True):
                        href = link["href"]
                        full_url = urljoin(url, href)
                        if urlparse(full_url).netloc == urlparse(self.target_url).netloc and full_url not in visited and depth < max_depth:
                            urls_to_visit.append((full_url, depth + 1))
                    for full_url in dynamic_links:
                        if urlparse(full_url).netloc == urlparse(self.target_url).netloc and full_url not in visited and depth < max_depth:
                            urls_to_visit.append((full_url, depth + 1))
                    for form in soup.find_all("form"):
                        form_data = self.extract_form_data(form, url)
                        if form_data:
                            self.forms.append(form_data)
                            self.log(f"Found form: {form_data['action']} ({form_data['method']})")
                            await self.send_websocket_message({
                                "type": "form_found",
                                "form": form_data,
                                "total_forms": len(self.forms),
                            })
                    for form_data in dynamic_forms:
                        if form_data not in self.forms:
                            self.forms.append(form_data)
                            self.log(f"Found dynamic form: {form_data['action']} ({form_data['method']})")
                            await self.send_websocket_message({
                                "type": "form_found",
                                "form": form_data,
                                "total_forms": len(self.forms),
                            })
            except Exception as e:
                self.log(f"Error crawling {url}: {str(e)}", "ERROR")

        self.log(f"Crawling completed. Found {len(self.discovered_urls)} URLs and {len(self.forms)} forms")
        await self.send_websocket_message({
            "type": "crawling_complete",
            "urls_found": len(self.discovered_urls),
            "forms_found": len(self.forms),
            "progress": 30,
        })

    async def scan_xss(self):
        """Enhanced XSS scan with real-time updates"""
        if "xss" not in self.scan_types or self._cancel:
            return

        self.log("Starting XSS vulnerability scan...")
        await self.send_websocket_message({
            "type": "phase_update",
            "phase": "xss_scanning",
            "progress": 40,
        })

        # Generate OAST payloads if enabled (blind XSS)
        oast_payloads = []
        if self.enable_oast and self.oast:
            try:
                oast_payloads = self.oast.generate_xss_payloads(self.scan_id)
                self.log(f"Generated {len(oast_payloads)} OAST XSS payloads")
            except Exception as e:
                self.log(f"OAST payload generation failed: {e}", "ERROR")

        # Inject OAST XSS payloads (they are designed to beacon back later)
        if oast_payloads:
            try:
                injection_points = 0
                # Forms
                for form in self.forms:
                    for input_name in form.get("inputs", []):
                        for p in oast_payloads:
                            payload_text = p.get("payload")
                            if not payload_text:
                                continue
                            data = {inp: (payload_text if inp == input_name else "test") for inp in form.get("inputs", [])}
                            try:
                                if form.get("method") == "post":
                                    self.session.post(form.get("action"), data=data, timeout=8)
                                else:
                                    self.session.get(form.get("action"), params=data, timeout=8)
                                injection_points += 1
                                await asyncio.sleep(self.delay)
                            except Exception:
                                pass
                # URL parameters
                from urllib.parse import urlparse, parse_qs
                for url in list(self.discovered_urls):
                    parsed = urlparse(url)
                    if not parsed.query:
                        continue
                    params = parse_qs(parsed.query)
                    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    for param_name in params.keys():
                        for p in oast_payloads:
                            payload_text = p.get("payload")
                            if not payload_text:
                                continue
                            test_params = {n: (payload_text if n == param_name else 'test') for n in params.keys()}
                            try:
                                self.session.get(base, params=test_params, timeout=8)
                                injection_points += 1
                                await asyncio.sleep(self.delay)
                            except Exception:
                                pass
                self.log(f"Injected {len(oast_payloads)} OAST XSS payload variants across {injection_points} points for blind callback detection")
            except Exception as e:
                self.log(f"Error injecting OAST XSS payloads: {e}", "ERROR")

        # Test forms for XSS
        for form in self.forms:
            for input_name in form["inputs"]:
                if self._cancel:
                    return
                for payload in self.xss_payloads:
                    if self._cancel:
                        return
                    self.current_url = form["action"]
                    self.current_payload = payload
                    self.log(
                        f"Testing XSS payload: {payload} in form {form['action']}"
                    )
                    await self.send_websocket_message({
                        "type": "payload_testing",
                        "scanner": "XSS",
                        "url": form["action"],
                        "parameter": input_name,
                        "payload": payload,
                        "method": form["method"],
                    })

                    # Prepare form data
                    data = {
                        inp: (payload if inp == input_name else "test")
                        for inp in form["inputs"]
                    }
                    try:
                        if form["method"] == "post":
                            response = self.session.post(
                                form["action"], data=data, timeout=10
                            )
                        else:
                            response = self.session.get(
                                form["action"], params=data, timeout=10
                            )
                        await asyncio.sleep(self.delay)
                        if self.is_xss_vulnerable(payload, response.text):
                            vuln = {
                                "type": "xss",
                                "url": form["action"],
                                "parameter": input_name,
                                "payload": payload,
                                "evidence": self.extract_xss_evidence(
                                    payload, response.text
                                ),
                                "method": form["method"],
                                "severity": "Medium",
                                "confidence": "High",
                            }
                            self.vulnerabilities.append(vuln)
                            self.log(
                                f"XSS vulnerability found: {form['action']} parameter={input_name}",
                                "VULN",
                            )
                            await self.send_websocket_message({
                                "type": "vulnerability_found",
                                "vulnerability": vuln,
                                "total_vulns": len(self.vulnerabilities),
                            })
                            # Persist to Mongo in background (optional mode)
                            try:
                                from mongo_service import mongo_service
                                from models import VulnerabilityDocument
                                from database import mongodb

                                if mongodb.is_connected() and self.scan_id:
                                    doc = VulnerabilityDocument(
                                        scan_id=self.scan_id,
                                        type=vuln["type"].lower(),
                                        url=vuln["url"],
                                        parameter=vuln.get("parameter"),
                                        payload=vuln.get("payload"),
                                        evidence=vuln.get("evidence") or "",
                                        severity=vuln.get("severity", "medium").lower(),
                                        cvss_score=None,
                                        epss_score=None,
                                        confidence=vuln.get("confidence"),
                                    )
                                    asyncio.create_task(
                                        mongo_service.create_vulnerability(doc)
                                    )
                            except Exception:
                                pass
                            break  # Found one, move to next parameter
                    except Exception as e:
                        self.log(
                            f"Error testing XSS on {form['action']}: {str(e)}",
                            "ERROR",
                        )

    # Test URLs with parameters for XSS
        from urllib.parse import urlparse, parse_qs

        for url in list(self.discovered_urls):
            if self._cancel:
                return
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param_name in params.keys():
                    if self._cancel:
                        return
                    for payload in self.xss_payloads:
                        if self._cancel:
                            return
                        self.current_url = url
                        self.current_payload = payload
                        self.log(
                            f"Testing XSS payload: {payload} in URL parameter {param_name}"
                        )
                        await self.send_websocket_message({
                            "type": "payload_testing",
                            "scanner": "XSS",
                            "url": url,
                            "parameter": param_name,
                            "payload": payload,
                            "method": "GET",
                        })

                        test_params = {
                            p: (payload if p == param_name else "test")
                            for p in params.keys()
                        }
                        try:
                            response = self.session.get(
                                f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                                params=test_params,
                                timeout=10,
                            )
                            await asyncio.sleep(self.delay)
                            if self.is_xss_vulnerable(payload, response.text):
                                vuln = {
                                    "type": "xss",
                                    "url": url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "evidence": self.extract_xss_evidence(
                                        payload, response.text
                                    ),
                                    "method": "GET",
                                    "severity": "Medium",
                                    "confidence": "High",
                                }
                                self.vulnerabilities.append(vuln)
                                self.log(
                                    f"XSS vulnerability found: {url} parameter={param_name}",
                                    "VULN",
                                )
                                await self.send_websocket_message({
                                    "type": "vulnerability_found",
                                    "vulnerability": vuln,
                                    "total_vulns": len(self.vulnerabilities),
                                })
                                try:
                                    from mongo_service import mongo_service
                                    from models import VulnerabilityDocument
                                    from database import mongodb

                                    if mongodb.is_connected() and self.scan_id:
                                        doc = VulnerabilityDocument(
                                            scan_id=self.scan_id,
                                            type=vuln["type"].lower(),
                                            url=vuln["url"],
                                            parameter=vuln.get("parameter"),
                                            payload=vuln.get("payload"),
                                            evidence=vuln.get("evidence") or "",
                                            severity=vuln.get("severity", "medium").lower(),
                                            cvss_score=None,
                                            epss_score=None,
                                            confidence=vuln.get("confidence"),
                                        )
                                        asyncio.create_task(
                                            mongo_service.create_vulnerability(doc)
                                        )
                                except Exception:
                                    pass
                                break
                        except Exception as e:
                            self.log(
                                f"Error testing XSS on {url}: {str(e)}", "ERROR"
                            )

        # Simple OAST callback polling (single pass) for blind XSS
        if self.enable_oast and self.oast and oast_payloads:
            try:
                hits = 0
                for p in oast_payloads:
                    pid = p.get("callback_id")
                    if pid and self.oast.check_callback(pid):
                        hits += 1
                if hits:
                    vuln = {
                        "type": "blind_xss_oast",
                        "url": self.target_url,
                        "parameter": "(oast)",
                        "payload": f"{hits} callbacks",
                        "evidence": "OAST collaborator reported callbacks",
                        "method": "N/A",
                        "severity": "High",
                        "confidence": "Medium",
                    }
                    self.vulnerabilities.append(vuln)
                    await self.send_websocket_message({
                        "type": "vulnerability_found",
                        "vulnerability": vuln,
                        "total_vulns": len(self.vulnerabilities),
                    })
                    # Persist OAST finding to Mongo
                    await self._persist_vulnerability_to_mongo(vuln)
            except Exception as e:
                self.log(f"OAST callback check failed: {e}", "ERROR")

    async def scan_sqli(self):
        """Enhanced SQLi scan with real-time updates"""
        if "sqli" not in self.scan_types or self._cancel:
            return

        self.log("Starting SQL injection vulnerability scan...")
        await self.send_websocket_message({
            "type": "phase_update",
            "phase": "sqli_scanning",
            "progress": 70,
        })

        # Generate OAST payloads if enabled (blind SQLi)
        oast_payloads = []
        if self.enable_oast and self.oast:
            try:
                oast_payloads = self.oast.generate_sqli_payloads(self.scan_id)
                self.log(f"Generated {len(oast_payloads)} OAST SQLi payloads")
            except Exception as e:
                self.log(f"OAST SQLi payload generation failed: {e}", "ERROR")

        # Inject OAST SQLi payloads to potential injection points (forms + URL params)
        if oast_payloads:
            try:
                injection_points = 0
                # Forms
                for form in self.forms:
                    for input_name in form.get("inputs", []):
                        for p in oast_payloads:
                            payload_text = p.get("payload")
                            if not payload_text:
                                continue
                            data = {inp: (payload_text if inp == input_name else "1") for inp in form.get("inputs", [])}
                            try:
                                if form.get("method") == "post":
                                    self.session.post(form.get("action"), data=data, timeout=8)
                                else:
                                    self.session.get(form.get("action"), params=data, timeout=8)
                                injection_points += 1
                                await asyncio.sleep(self.delay)
                            except Exception:
                                pass
                # URL parameters
                from urllib.parse import urlparse, parse_qs
                for url in list(self.discovered_urls):
                    parsed = urlparse(url)
                    if not parsed.query:
                        continue
                    params = parse_qs(parsed.query)
                    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    for param_name in params.keys():
                        for p in oast_payloads:
                            payload_text = p.get("payload")
                            if not payload_text:
                                continue
                            test_params = {n: (payload_text if n == param_name else '1') for n in params.keys()}
                            try:
                                self.session.get(base, params=test_params, timeout=8)
                                injection_points += 1
                                await asyncio.sleep(self.delay)
                            except Exception:
                                pass
                self.log(f"Injected {len(oast_payloads)} OAST SQLi payload variants across {injection_points} points for blind callback detection")
            except Exception as e:
                self.log(f"Error injecting OAST SQLi payloads: {e}", "ERROR")

        # Test forms for SQLi
        for form in self.forms:
            for input_name in form["inputs"]:
                if self._cancel:
                    return
                for payload in self.sqli_payloads:
                    if self._cancel:
                        return
                    self.current_url = form["action"]
                    self.current_payload = payload
                    self.log(
                        f"Testing SQLi payload: {payload} in form {form['action']}"
                    )

                    await self.send_websocket_message({
                        "type": "payload_testing",
                        "scanner": "SQLi",
                        "url": form["action"],
                        "parameter": input_name,
                        "payload": payload,
                        "method": form["method"],
                    })

                    data = {
                        inp: (payload if inp == input_name else "test")
                        for inp in form["inputs"]
                    }

                    try:
                        if form["method"] == "post":
                            response = self.session.post(
                                form["action"], data=data, timeout=10
                            )
                        else:
                            response = self.session.get(
                                form["action"], params=data, timeout=10
                            )

                        await asyncio.sleep(self.delay)

                        if self.is_sqli_vulnerable(response):
                            vuln = {
                                "type": "sqli",
                                "url": form["action"],
                                "parameter": input_name,
                                "payload": payload,
                                "evidence": self.extract_sqli_evidence(response.text),
                                "method": form["method"],
                                "severity": "High",
                                "confidence": "High",
                            }
                            self.vulnerabilities.append(vuln)
                            self.log(
                                f"SQL injection vulnerability found: {form['action']} parameter={input_name}",
                                "VULN",
                            )

                            await self.send_websocket_message({
                                "type": "vulnerability_found",
                                "vulnerability": vuln,
                                "total_vulns": len(self.vulnerabilities),
                            })
                            try:
                                from mongo_service import mongo_service
                                from models import VulnerabilityDocument
                                from database import mongodb

                                if mongodb.is_connected() and self.scan_id:
                                    doc = VulnerabilityDocument(
                                        scan_id=self.scan_id,
                                        type=vuln["type"].lower(),
                                        url=vuln["url"],
                                        parameter=vuln.get("parameter"),
                                        payload=vuln.get("payload"),
                                        evidence=vuln.get("evidence") or "",
                                        severity=vuln.get("severity", "high").lower(),
                                        cvss_score=None,
                                        epss_score=None,
                                        confidence=vuln.get("confidence"),
                                    )
                                    asyncio.create_task(
                                        mongo_service.create_vulnerability(doc)
                                    )
                            except Exception:
                                pass
                            break
                    except Exception as e:
                        self.log(
                            f"Error testing SQLi on {form['action']}: {str(e)}",
                            "ERROR",
                        )

        # OAST callback polling for blind SQLi
        if self.enable_oast and self.oast and oast_payloads:
            try:
                hits = 0
                for p in oast_payloads:
                    pid = p.get("callback_id")
                    if pid and self.oast.check_callback(pid):
                        hits += 1
                if hits:
                    vuln = {
                        "type": "blind_sqli_oast",
                        "url": self.target_url,
                        "parameter": "(oast)",
                        "payload": f"{hits} callbacks",
                        "evidence": "OAST collaborator reported SQLi callbacks",
                        "method": "N/A",
                        "severity": "High",
                        "confidence": "Medium",
                    }
                    self.vulnerabilities.append(vuln)
                    await self.send_websocket_message({
                        "type": "vulnerability_found",
                        "vulnerability": vuln,
                        "total_vulns": len(self.vulnerabilities),
                    })
                    # Persist OAST finding to Mongo
                    await self._persist_vulnerability_to_mongo(vuln)
            except Exception as e:
                self.log(f"OAST SQLi callback check failed: {e}", "ERROR")

    async def run_scan(self):
        """Run the complete vulnerability scan with real-time updates"""
        self.log(f"Starting vulnerability scan for: {self.target_url}")
        self.log(f"Scan types: {', '.join(self.scan_types)}")
        if self._cancel:
            return []

        await self.send_websocket_message({
            "type": "scan_started",
            "target": self.target_url,
            "scan_types": self.scan_types,
        })

        # Phase 1: Crawling
        await self.crawl_website()
        if self._cancel:
            return self.vulnerabilities

        # Phase 2: Vulnerability Testing
        if "xss" in self.scan_types:
            await self.scan_xss()
            if self._cancel:
                return self.vulnerabilities

        if "sqli" in self.scan_types:
            await self.scan_sqli()
            if self._cancel:
                return self.vulnerabilities

        if "csrf" in self.scan_types:
            await self.scan_csrf()
            if self._cancel:
                return self.vulnerabilities

        if "security_misconfiguration" in self.scan_types:
            await self.scan_security_misconfiguration()
            if self._cancel:
                return self.vulnerabilities

        if "vulnerable_components" in self.scan_types:
            await self.scan_vulnerable_components()
            if self._cancel:
                return self.vulnerabilities

        if "ssrf" in self.scan_types:
            await self.scan_ssrf()
            if self._cancel:
                return self.vulnerabilities

        if "broken_access_control" in self.scan_types:
            await self.scan_broken_access_control()
            if self._cancel:
                return self.vulnerabilities

        if "cryptographic_failures" in self.scan_types:
            await self.scan_cryptographic_failures()
            if self._cancel:
                return self.vulnerabilities

        if "authentication_failures" in self.scan_types:
            await self.scan_authentication_failures()
            if self._cancel:
                return self.vulnerabilities

        if "integrity_failures" in self.scan_types:
            await self.scan_integrity_failures()
            if self._cancel:
                return self.vulnerabilities

        if "logging_monitoring_failures" in self.scan_types:
            await self.scan_logging_monitoring_failures()
            if self._cancel:
                return self.vulnerabilities

        self.log(f"Scan completed. Found {len(self.vulnerabilities)} vulnerabilities")
        await self.send_websocket_message({
            "type": "scan_complete",
            "vulnerabilities_found": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities,
            "progress": 100,
        })
        return self.vulnerabilities

    async def scan_security_misconfiguration(self):
        """Security Misconfiguration scanning with real-time updates"""
        if "security_misconfiguration" not in self.scan_types or self._cancel:
            return

        self.log("Starting Security Misconfiguration scan...")
        await self.send_websocket_message({
            "type": "phase_update",
            "phase": "security_misconfiguration_scanning",
            "message": "Scanning for security misconfigurations...",
        })

        # Prepare attack surface for the scanner
        attack_surface = {"urls": [(url, []) for url in list(self.discovered_urls)]}
        try:
            findings = await self.security_misconfiguration_scanner.scan(attack_surface)
            for finding in findings:
                if self._cancel:
                    return
                vulnerability = {
                    "type": "security_misconfiguration",
                    "severity": finding["severity"],
                    "url": finding["url"],
                    "parameter": finding["parameter"],
                    "payload": finding["payload"],
                    "evidence": finding["evidence"],
                    "remediation": finding["remediation"],
                    "confidence": finding["confidence"],
                    "cvss": self._calculate_cvss(finding["severity"]),
                    "epss": 0.1,
                    "timestamp": time.time(),
                }
                self.vulnerabilities.append(vulnerability)
                await self.send_websocket_message({
                    "type": "vulnerability_found",
                    "vulnerability": vulnerability,
                    "total_found": len(self.vulnerabilities),
                })
                self.log(
                    f"Security Misconfiguration found: {finding['evidence']}",
                    "WARNING",
                )
                try:
                    from mongo_service import mongo_service
                    from models import VulnerabilityDocument
                    from database import mongodb

                    if mongodb.is_connected() and self.scan_id:
                        doc = VulnerabilityDocument(
                            scan_id=self.scan_id,
                            type=vulnerability["type"].lower(),
                            url=vulnerability["url"],
                            parameter=vulnerability.get("parameter"),
                            payload=vulnerability.get("payload"),
                            evidence=vulnerability.get("evidence") or "",
                            severity=vulnerability.get("severity", "medium").lower(),
                            cvss_score=None,
                            epss_score=None,
                            confidence=vulnerability.get("confidence"),
                        )
                        asyncio.create_task(
                            mongo_service.create_vulnerability(doc)
                        )
                except Exception:
                    pass
        except Exception as e:
            self.log(f"Error during security misconfiguration scan: {e}", "ERROR")

    async def scan_vulnerable_components(self):
        """Vulnerable Components scanning with real-time updates"""
        if "vulnerable_components" not in self.scan_types or self._cancel:
            return

        self.log("Starting Vulnerable Components scan...")
        await self.send_websocket_message({
            "type": "phase_update",
            "phase": "vulnerable_components_scanning",
            "message": "Scanning for vulnerable components...",
        })

        # Prepare attack surface for the scanner
        attack_surface = {"urls": [(url, []) for url in list(self.discovered_urls)]}
        try:
            findings = await self.vulnerable_components_scanner.scan(attack_surface)
            for finding in findings:
                if self._cancel:
                    return
                vulnerability = {
                    "type": "vulnerable_components",
                    "severity": finding["severity"],
                    "url": finding["url"],
                    "parameter": finding["parameter"],
                    "payload": finding["payload"],
                    "evidence": finding["evidence"],
                    "remediation": finding["remediation"],
                    "confidence": finding["confidence"],
                    "cvss": self._calculate_cvss(finding["severity"]),
                    "epss": 0.2,
                    "timestamp": time.time(),
                }
                self.vulnerabilities.append(vulnerability)
                await self.send_websocket_message({
                    "type": "vulnerability_found",
                    "vulnerability": vulnerability,
                    "total_found": len(self.vulnerabilities),
                })
                self.log(
                    f"Vulnerable Component found: {finding['evidence']}", "WARNING"
                )
                try:
                    from mongo_service import mongo_service
                    from models import VulnerabilityDocument
                    from database import mongodb

                    if mongodb.is_connected() and self.scan_id:
                        doc = VulnerabilityDocument(
                            scan_id=self.scan_id,
                            type=vulnerability["type"].lower(),
                            url=vulnerability["url"],
                            parameter=vulnerability.get("parameter"),
                            payload=vulnerability.get("payload"),
                            evidence=vulnerability.get("evidence") or "",
                            severity=vulnerability.get("severity", "medium").lower(),
                            cvss_score=None,
                            epss_score=None,
                            confidence=vulnerability.get("confidence"),
                        )
                        asyncio.create_task(
                            mongo_service.create_vulnerability(doc)
                        )
                except Exception:
                    pass
        except Exception as e:
            self.log(f"Error during vulnerable components scan: {e}", "ERROR")

    async def scan_ssrf(self):
        """SSRF scanning with real-time updates"""
        if "ssrf" not in self.scan_types or self._cancel:
            return

        self.log("Starting SSRF scan...")
        await self.send_websocket_message({
            "type": "phase_update",
            "phase": "ssrf_scanning",
            "message": "Scanning for SSRF vulnerabilities...",
        })

        # Generate OAST payloads if enabled (blind SSRF)
        oast_payloads = []
        if self.enable_oast and self.oast:
            try:
                # Generate simple SSRF OAST URLs
                oast_payloads = []
                for i in range(5):  # Generate 5 SSRF OAST payloads
                    callback_id = self.oast.generate_callback_id()
                    subdomain = self.oast.generate_subdomain()
                    callback_url = f"http://{subdomain}/ssrf"
                    oast_payloads.append({
                        "callback_id": callback_id,
                        "payload": callback_url,
                        "callback_url": callback_url
                    })
                self.log(f"Generated {len(oast_payloads)} OAST SSRF payloads")
            except Exception as e:
                self.log(f"OAST SSRF payload generation failed: {e}", "ERROR")

        # Inject OAST SSRF payloads into likely SSRF parameters (heuristic)
        if oast_payloads:
            try:
                ssrf_param_names = {"url","uri","path","target","dest","redirect","next","feed","u","link","callback"}
                injection_points = 0
                # Forms
                for form in self.forms:
                    inputs = form.get("inputs", [])
                    candidate_inputs = [i for i in inputs if i.lower() in ssrf_param_names]
                    if not candidate_inputs:
                        continue
                    for input_name in candidate_inputs:
                        for p in oast_payloads:
                            payload_url = p.get("payload")
                            if not payload_url:
                                continue
                            data = {inp: (payload_url if inp == input_name else "http://example.com") for inp in inputs}
                            try:
                                if form.get("method") == "post":
                                    self.session.post(form.get("action"), data=data, timeout=8)
                                else:
                                    self.session.get(form.get("action"), params=data, timeout=8)
                                injection_points += 1
                                await asyncio.sleep(self.delay)
                            except Exception:
                                pass
                # URL parameters
                from urllib.parse import urlparse, parse_qs
                for url in list(self.discovered_urls):
                    parsed = urlparse(url)
                    if not parsed.query:
                        continue
                    params = parse_qs(parsed.query)
                    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    candidate_params = [n for n in params.keys() if n.lower() in ssrf_param_names]
                    if not candidate_params:
                        continue
                    for param_name in candidate_params:
                        for p in oast_payloads:
                            payload_url = p.get("payload")
                            if not payload_url:
                                continue
                            test_params = {n: (payload_url if n == param_name else 'http://example.com') for n in params.keys()}
                            try:
                                self.session.get(base, params=test_params, timeout=8)
                                injection_points += 1
                                await asyncio.sleep(self.delay)
                            except Exception:
                                pass
                self.log(f"Injected {len(oast_payloads)} OAST SSRF payload variants across {injection_points} points for blind callback detection")
            except Exception as e:
                self.log(f"Error injecting OAST SSRF payloads: {e}", "ERROR")

        # Prepare attack surface for the scanner
        attack_surface = {
            "urls": [
                (url, self.forms) for url in list(self.discovered_urls)
            ]
        }
        try:
            findings = await self.ssrf_scanner.scan(attack_surface)
            for finding in findings:
                if self._cancel:
                    return
                vulnerability = {
                    "type": "ssrf",
                    "severity": finding["severity"],
                    "url": finding["url"],
                    "parameter": finding["parameter"],
                    "payload": finding["payload"],
                    "evidence": finding["evidence"],
                    "remediation": finding["remediation"],
                    "confidence": finding["confidence"],
                    "cvss": self._calculate_cvss(finding["severity"]),
                    "epss": 0.3,
                    "timestamp": time.time(),
                }
                self.vulnerabilities.append(vulnerability)
                await self.send_websocket_message({
                    "type": "vulnerability_found",
                    "vulnerability": vulnerability,
                    "total_found": len(self.vulnerabilities),
                })
                self.log(
                    f"SSRF vulnerability found: {finding['evidence']}", "WARNING"
                )
                try:
                    from mongo_service import mongo_service
                    from models import VulnerabilityDocument
                    from database import mongodb

                    if mongodb.is_connected() and self.scan_id:
                        doc = VulnerabilityDocument(
                            scan_id=self.scan_id,
                            type=vulnerability["type"].lower(),
                            url=vulnerability["url"],
                            parameter=vulnerability.get("parameter"),
                            payload=vulnerability.get("payload"),
                            evidence=vulnerability.get("evidence") or "",
                            severity=vulnerability.get("severity", "medium").lower(),
                            cvss_score=None,
                            epss_score=None,
                            confidence=vulnerability.get("confidence"),
                        )
                        asyncio.create_task(
                            mongo_service.create_vulnerability(doc)
                        )
                except Exception:
                    pass

            # OAST callback polling for blind SSRF
            if self.enable_oast and self.oast and oast_payloads:
                try:
                    hits = 0
                    for p in oast_payloads:
                        pid = p.get("callback_id")
                        if pid and self.oast.check_callback(pid):
                            hits += 1
                    if hits:
                        vuln = {
                            "type": "blind_ssrf_oast",
                            "url": self.target_url,
                            "parameter": "(oast)",
                            "payload": f"{hits} callbacks",
                            "evidence": "OAST collaborator reported SSRF callbacks",
                            "method": "N/A",
                            "severity": "High",
                            "confidence": "Medium",
                        }
                        self.vulnerabilities.append(vuln)
                        await self.send_websocket_message({
                            "type": "vulnerability_found",
                            "vulnerability": vuln,
                            "total_vulns": len(self.vulnerabilities),
                        })
                        # Persist OAST finding to Mongo
                        await self._persist_vulnerability_to_mongo(vuln)
                except Exception as e:
                    self.log(f"OAST SSRF callback check failed: {e}", "ERROR")
                    
        except Exception as e:
            self.log(f"Error during SSRF scan: {e}", "ERROR")

    async def scan_csrf(self):
        """CSRF scanning with real-time updates (token presence and SameSite checks)"""
        if "csrf" not in self.scan_types or self._cancel:
            return

        self.log("Starting CSRF scan...")
        await self.send_websocket_message({
            "type": "phase_update",
            "phase": "csrf_scanning",
            "message": "Scanning for CSRF risks...",
        })

        # Prepare attack surface for the scanner (convert our form schema to expected keys)
        forms_for_csrf = [
            {"url": f.get("action"), "method": f.get("method"), "inputs": f.get("inputs", [])}
            for f in self.forms
        ]
        attack_surface = {
            "forms": forms_for_csrf,
            "urls": [(url, []) for url in list(self.discovered_urls)],
        }

        try:
            findings = []
            if self.csrf_scanner:
                findings = await asyncio.to_thread(self.csrf_scanner.scan, attack_surface)
            else:
                self.log("CSRF scanner unavailable", "ERROR")

            for f in findings or []:
                if self._cancel:
                    return
                # CSRFScanner returns Vulnerability dataclass; normalize fields
                vuln = {
                    "type": "csrf",
                    "severity": "Medium",
                    "url": getattr(f, "url", None) or (f.get("url") if isinstance(f, dict) else self.target_url),
                    "parameter": getattr(f, "parameter", None) or (f.get("parameter") if isinstance(f, dict) else None),
                    "payload": getattr(f, "payload", None) or (f.get("payload") if isinstance(f, dict) else None),
                    "evidence": getattr(f, "evidence", None) or (f.get("evidence") if isinstance(f, dict) else "CSRF risk detected"),
                    "remediation": "Implement anti-CSRF tokens and set SameSite on session cookies",
                    "confidence": getattr(f, "confidence", None) or (f.get("confidence") if isinstance(f, dict) else "Medium"),
                    "cvss": self._calculate_cvss("Medium"),
                    "epss": 0.25,
                    "timestamp": time.time(),
                }
                self.vulnerabilities.append(vuln)
                await self.send_websocket_message({
                    "type": "vulnerability_found",
                    "vulnerability": vuln,
                    "total_found": len(self.vulnerabilities),
                })
                self.log(f"CSRF risk found: {vuln['evidence']}", "WARNING")
                # Persist to Mongo if connected
                try:
                    from mongo_service import mongo_service
                    from models import VulnerabilityDocument
                    from database import mongodb

                    if mongodb.is_connected() and self.scan_id:
                        doc = VulnerabilityDocument(
                            scan_id=self.scan_id,
                            type=vuln["type"].lower(),
                            url=vuln["url"],
                            parameter=vuln.get("parameter"),
                            payload=vuln.get("payload"),
                            evidence=vuln.get("evidence") or "",
                            severity=vuln.get("severity", "medium").lower(),
                            cvss_score=None,
                            epss_score=None,
                            confidence=vuln.get("confidence"),
                        )
                        asyncio.create_task(mongo_service.create_vulnerability(doc))
                except Exception:
                    pass
        except Exception as e:
            self.log(f"Error during CSRF scan: {e}", "ERROR")

    def _calculate_cvss(self, severity: str) -> float:
        """Calculate CVSS score based on severity"""
        severity_scores = {
            "Critical": 9.5,
            "High": 7.5,
            "Medium": 5.0,
            "Low": 2.5,
            "Info": 0.5,
        }
        return severity_scores.get(severity, 5.0)

    async def _persist_vulnerability_to_mongo(self, vuln: dict):
        """Helper to persist vulnerability to MongoDB"""
        try:
            from mongo_service import mongo_service
            from models import VulnerabilityDocument
            from database import mongodb
            
            if mongodb.is_connected() and self.scan_id:
                doc = VulnerabilityDocument(
                    scan_id=self.scan_id,
                    type=vuln["type"].lower(),
                    url=vuln.get("url") or self.target_url,
                    parameter=vuln.get("parameter"),
                    payload=vuln.get("payload"),
                    evidence=vuln.get("evidence") or "",
                    severity=vuln.get("severity", "medium").lower(),
                    cvss_score=None,
                    epss_score=None,
                    confidence=vuln.get("confidence"),
                )
                asyncio.create_task(mongo_service.create_vulnerability(doc))
        except Exception as e:
            self.log(f"Error persisting vulnerability to Mongo: {e}", "ERROR")

    async def _run_simple_scanner(self, name: str, scanner, transform_type: str, surface_builder):
        if not scanner:
            return
        self.log(f"Starting {name} scan...")
        await self.send_websocket_message({
            "type": "phase_update",
            "phase": f"{name}_scanning",
            "message": f"Scanning for {name.replace('_', ' ')}...",
        })
        try:
            attack_surface = surface_builder()
            # Run potentially blocking scan in thread pool
            findings = await asyncio.to_thread(scanner.scan, attack_surface)
            for f in findings:
                if self._cancel:
                    return
                vuln = {
                    "type": transform_type,
                    "severity": "Medium",  # heuristic default
                    "url": getattr(f, 'url', ''),
                    "parameter": getattr(f, 'parameter', ''),
                    "payload": getattr(f, 'payload', ''),
                    "evidence": getattr(f, 'evidence', ''),
                    "remediation": getattr(f, 'remediation', 'See remediation guidance'),
                    "confidence": getattr(f, 'confidence', 'Medium'),
                    "cvss": self._calculate_cvss("Medium"),
                    "epss": 0.15,
                    "timestamp": time.time(),
                }
                self.vulnerabilities.append(vuln)
                await self.send_websocket_message({
                    "type": "vulnerability_found",
                    "vulnerability": vuln,
                    "total_found": len(self.vulnerabilities),
                })
                # Persist to Mongo so analytics picks up new categories
                try:
                    from mongo_service import mongo_service
                    from models import VulnerabilityDocument
                    from database import mongodb
                    if mongodb.is_connected() and self.scan_id:
                        doc = VulnerabilityDocument(
                            scan_id=self.scan_id,
                            type=vuln["type"].lower(),
                            url=vuln.get("url") or self.target_url,
                            parameter=vuln.get("parameter"),
                            payload=vuln.get("payload"),
                            evidence=vuln.get("evidence") or "",
                            severity=vuln.get("severity", "medium").lower(),
                            cvss_score=None,
                            epss_score=None,
                            confidence=vuln.get("confidence"),
                        )
                        asyncio.create_task(mongo_service.create_vulnerability(doc))
                except Exception:
                    pass
        except Exception as e:
            self.log(f"Error during {name} scan: {e}", "ERROR")

    async def scan_broken_access_control(self):
        await self._run_simple_scanner(
            "broken_access_control",
            self.bac_scanner,
            "broken_access_control",
            lambda: {"urls": [(u, []) for u in list(self.discovered_urls)]}
        )

    async def scan_cryptographic_failures(self):
        await self._run_simple_scanner(
            "cryptographic_failures",
            self.crypto_scanner,
            "cryptographic_failures",
            lambda: {"urls": [(u, []) for u in list(self.discovered_urls)]}
        )

    async def scan_authentication_failures(self):
        await self._run_simple_scanner(
            "authentication_failures",
            self.auth_scanner,
            "authentication_failures",
            lambda: {"forms": self.forms, "urls": [(u, []) for u in list(self.discovered_urls)]}
        )

    async def scan_integrity_failures(self):
        await self._run_simple_scanner(
            "integrity_failures",
            self.integrity_scanner,
            "integrity_failures",
            lambda: {"urls": [(u, []) for u in list(self.discovered_urls)]}
        )

    async def scan_logging_monitoring_failures(self):
        await self._run_simple_scanner(
            "logging_monitoring_failures",
            self.logmon_scanner,
            "logging_monitoring_failures",
            lambda: {"urls": [(u, []) for u in list(self.discovered_urls)]}
        )
