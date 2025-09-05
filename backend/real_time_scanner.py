import asyncio
from scanner import VulnerabilityScanner
from typing import Dict, List, Any, Optional
import json
import time

# Import the new scanners
from scanners.security_misconfiguration_scanner import SecurityMisconfigurationScanner
from scanners.vulnerable_components_scanner import VulnerableComponentsScanner
from scanners.ssrf_scanner import SSRFScanner


class RealTimeScanner(VulnerabilityScanner):
    def __init__(self, target_url, scan_types, verbose=False, delay=0.1, websocket_manager=None, log_callback=None):
        super().__init__(target_url, scan_types, verbose, delay)
        self.websocket_manager = websocket_manager
        self.log_callback = log_callback
        self.scan_id: Optional[str] = None
        self.current_url = ""
        self.current_payload = ""
        self._cancel = False

        # Initialize specialized scanners
        self.security_misconfiguration_scanner = SecurityMisconfigurationScanner(websocket_manager)
        self.vulnerable_components_scanner = VulnerableComponentsScanner(websocket_manager)
        self.ssrf_scanner = SSRFScanner(websocket_manager)

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
        """Enhanced crawl with real-time updates"""
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

        urls_to_visit = [(self.target_url, 0)]
        visited = set()

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
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, "html.parser")
                    # links
                    for link in soup.find_all("a", href=True):
                        href = link["href"]
                        full_url = urljoin(url, href)
                        if urlparse(full_url).netloc == urlparse(self.target_url).netloc:
                            if full_url not in visited and depth < max_depth:
                                urls_to_visit.append((full_url, depth + 1))
                    # forms
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
            except Exception as e:
                self.log(f"Error crawling {url}: {str(e)}", "ERROR")

        self.log(
            f"Crawling completed. Found {len(self.discovered_urls)} URLs and {len(self.forms)} forms"
        )
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
        except Exception as e:
            self.log(f"Error during SSRF scan: {e}", "ERROR")

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
