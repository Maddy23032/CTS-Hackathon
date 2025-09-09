from vulnerability import Vulnerability
from .ssrf_scanner import calculate_cvss_4  # Use relative import for CVSS function

class XSSScanner:
    def __init__(self, session, payloads, verbose=False, oast_collaborator=None):
        self.session = session
        self.payloads = payloads
        self.verbose = verbose
        self.oast_collaborator = oast_collaborator

    def log(self, msg):
        if self.verbose:
            print(f"[XSSScanner] {msg}")

    def scan(self, attack_surface):
        findings = []
        # Test URL parameters
        for url, params in attack_surface.get('urls', []):
            for param in params:
                # Test basic reflected XSS
                for payload in self.payloads:
                    test_params = {p: (payload if p == param else 'test') for p in params}
                    try:
                        resp = self.session.get(url, params=test_params, timeout=10)
                        if self.is_reflected(payload, resp.text):
                            evidence = self.extract_evidence(payload, resp.text)
                            findings.append(Vulnerability(
                                vulnerability_type="xss",
                                url=url,
                                parameter=param,
                                payload=payload,
                                evidence=evidence,
                                cvss=calculate_cvss_4("xss", "Medium", "High")  # Use CVSS calculation
                            ))
                            self.log(f"XSS found: {url} param={param} payload={payload}")
                            break  # Only report first payload that triggers reflection
                    except Exception as e:
                        self.log(f"Request failed: {e}")
                
                # OAST logic for blind XSS
                if self.oast_collaborator:
                    self._test_blind_xss_url_param(url, param, params, findings)
        # Test forms (GET/POST)
        for form in attack_surface.get('forms', []):
            url = form['url']
            method = form['method']
            inputs = form['inputs']
            for param in inputs:
                for payload in self.payloads:
                    data = {p: (payload if p == param else 'test') for p in inputs}
                    try:
                        if method == 'post':
                            resp = self.session.post(url, data=data, timeout=10)
                        else:
                            resp = self.session.get(url, params=data, timeout=10)
                        if self.is_reflected(payload, resp.text):
                            evidence = self.extract_evidence(payload, resp.text)
                            findings.append(Vulnerability(
                                vulnerability_type="xss",
                                url=url,
                                parameter=param,
                                payload=payload,
                                evidence=evidence,
                                cvss=calculate_cvss_4("xss", "Medium", "High")  # Use CVSS calculation
                            ))
                            self.log(f"XSS found: {url} param={param} payload={payload}")
                            break
                    except Exception as e:
                        self.log(f"Request failed: {e}")
                # If OAST is available, test for blind XSS
                if self.oast_collaborator:
                    self._test_blind_xss_form_param(url, method, param, inputs, findings)
        
        return findings

    def is_reflected(self, payload, text):
        # Simple reflection check (case-sensitive)
        return payload in text

    def extract_evidence(self, payload, text):
        # Return a snippet of the response containing the payload
        idx = text.find(payload)
        if idx != -1:
            start = max(0, idx - 40)
            end = min(len(text), idx + len(payload) + 40)
            return text[start:end]
        return text[:200]

    def _test_blind_xss_url_param(self, url, param, params, findings):
        """Test for blind XSS using OAST callbacks on URL parameters"""
        if not self.oast_collaborator:
            return
            
        # Generate OAST payloads for XSS
        oast_payloads = self.oast_collaborator.generate_xss_payloads()
        
        for payload_info in oast_payloads:
            payload = payload_info['payload']
            callback_id = payload_info['callback_id']
            self.log(f"[OAST-GET] Testing blind XSS {url} param={param} payload={payload}")
            
            try:
                test_params = {p: (payload if p == param else 'test') for p in params}
                resp = self.session.get(url, params=test_params, timeout=10)
                
                # Wait briefly for callback (XSS may trigger later when page is viewed)
                import time
                time.sleep(3)
                
                # Check if we received a callback
                if self.oast_collaborator.check_callback(callback_id):
                    self.log(f"BLIND XSS detected via OAST: {url} param={param}")
                    findings.append(Vulnerability(
                        vulnerability_type="Blind XSS (OAST)",
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence="OAST callback received indicating successful blind XSS execution",
                        confidence="High"
                    ))
                    break  # Found vulnerability, no need to test other payloads
                    
            except Exception as e:
                self.log(f"OAST request failed: {e}")

    def _test_blind_xss_form_param(self, url, method, param, inputs, findings):
        """Test for blind XSS using OAST callbacks on form parameters"""
        if not self.oast_collaborator:
            return
        if 'csrf' in param.lower():
            return
        oast_payloads = self.oast_collaborator.generate_xss_payloads()
        for payload_info in oast_payloads:
            payload = payload_info['payload']
            callback_id = payload_info['callback_id']
            data = {p: (payload if p == param else 'test') for p in inputs}
            self.log(f"[OAST-{method.upper()}] Testing blind XSS {url} param={param} payload={payload}")
            try:
                if method == 'post':
                    resp = self.session.post(url, data=data, timeout=10)
                else:
                    resp = self.session.get(url, params=data, timeout=10)
                import time
                time.sleep(3)
                if self.oast_collaborator.check_callback(callback_id):
                    self.log(f"BLIND XSS detected via OAST: {url} param={param}")
                    findings.append(Vulnerability(
                        vulnerability_type="Blind XSS (OAST)",
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence="OAST callback received indicating successful blind XSS execution",
                        confidence="High"
                    ))
                    break
            except Exception as e:
                self.log(f"OAST request failed: {e}")
