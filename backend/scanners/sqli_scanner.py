import re
from vulnerability import Vulnerability
from .ssrf_scanner import calculate_cvss_4  # Use relative import for CVSS function

class SQLiScanner:
	ERROR_SIGNATURES = [
		r"you have an error in your sql syntax",
		r"warning: mysql_",
		r"mysql_fetch",
		r"supplied argument is not a valid mysql",
		r"pg_query\(\): query failed",
		r"pg_exec\(\): query failed",
		r"unclosed quotation mark after the character string",
		r"quoted string not properly terminated",
		r"sql syntax.*?mysql",
		r"syntax error",
		r"odbc sql server driver",
		r"ora-00933",
		r"ora-01756",
		r"conversion failed when converting the varchar value",
		r"invalid input syntax for type",
		r"unterminated quoted string"
	]

	def __init__(self, session, payloads, verbose=False, oast_collaborator=None):
		self.session = session
		self.payloads = payloads
		self.verbose = verbose
		self.oast_collaborator = oast_collaborator
		self.max_post_attempts = 50

	def log(self, msg):
		if self.verbose:
			print(f"[SQLiScanner] {msg}")

	def scan(self, attack_surface):
		findings = []
		# Test URL parameters
		for url, params in attack_surface.get('urls', []):
			for param in params:
				# First test basic error-based payloads
				for payload in self.payloads:
					test_params = {p: (payload if p == param else 'test') for p in params}
					self.log(f"[GET] Testing {url} param={param} payload={payload}")
					try:
						resp = self.session.get(url, params=test_params, timeout=10)
						if self.is_injection_successful(payload, resp.text):
							evidence = self.extract_evidence(payload, resp.text)
							findings.append(Vulnerability(
								vulnerability_type="sqli",
								url=url,
								parameter=param,
								payload=payload,
								evidence=evidence,
								cvss=calculate_cvss_4("sqli", "High", "High")
							))
							self.log(f"SQLi found: {url} param={param} payload={payload}")
							break  # Only report first payload that triggers error
					except Exception as e:
						self.log(f"Request failed: {e}")
				
				# OAST logic for blind SQLi
				if self.oast_collaborator:
					self._test_blind_sqli_url_param(url, param, params, findings)
		# Test forms (only GET/POST)
		max_post_attempts = 10
		post_attempts = 0
		for form in attack_surface.get('forms', []):
			url = form['url']
			method = form['method']
			inputs = form['inputs']
			for param in inputs:
				# Test basic error-based payloads
				for payload in self.payloads:
					data = {p: (payload if p == param else 'test') for p in inputs}
					self.log(f"[{method.upper()}] Testing {url} param={param} payload={payload}")
					try:
						if method == 'post':
							resp = self.session.post(url, data=data, timeout=10)
							post_attempts += 1
						else:
							resp = self.session.get(url, params=data, timeout=10)
						if self.is_injection_successful(payload, resp.text):
							evidence = self.extract_evidence(payload, resp.text)
							findings.append(Vulnerability(
								vulnerability_type="sqli",
								url=url,
								parameter=param,
								payload=payload,
								evidence=evidence,
								cvss=calculate_cvss_4("sqli", "High", "High")
							))
							self.log(f"SQLi found: {url} param={param} payload={payload}")
							break
					except Exception as e:
						self.log(f"Request failed: {e}")
				# OAST logic for blind SQLi
				if self.oast_collaborator:
					self._test_blind_sqli_form_param(url, method, param, inputs, findings)
		
		return findings

	def is_error(self, text):
		text_lower = text.lower()
		for sig in self.ERROR_SIGNATURES:
			if re.search(sig, text_lower):
				return True
		return False

	def extract_evidence(self, text):
		# Return a snippet of the error message for reporting
		text_lower = text.lower()
		for sig in self.ERROR_SIGNATURES:
			m = re.search(sig, text_lower)
			if m:
				start = max(0, m.start() - 40)
				end = min(len(text), m.end() + 40)
				return text[m.start():end]
		return text[:200]

	def _test_blind_sqli_url_param(self, url, param, params, findings):
		"""Test for blind SQLi using OAST callbacks on URL parameters"""
		if not self.oast_collaborator:
			return
			
		# Generate OAST payloads for different database types
		oast_payloads = self.oast_collaborator.generate_sqli_payloads()
		
		for payload_info in oast_payloads:
			payload = payload_info['payload']
			callback_id = payload_info['callback_id']
			self.log(f"[OAST-GET] Testing blind SQLi {url} param={param} payload={payload}")
			
			try:
				test_params = {p: (payload if p == param else 'test') for p in params}
				resp = self.session.get(url, params=test_params, timeout=10)
				
				# Wait briefly for callback
				import time
				time.sleep(3)
				
				# Check if we received a callback
				if self.oast_collaborator.check_callback(callback_id):
					self.log(f"BLIND SQLi detected via OAST: {url} param={param}")
					findings.append(Vulnerability(
						vulnerability_type="Blind SQLi (OAST)",
						url=url,
						parameter=param,
						payload=payload,
						evidence="OAST callback received indicating successful blind SQLi execution",
						confidence="High"
					))
					break  # Found vulnerability, no need to test other DB types
					
			except Exception as e:
				self.log(f"OAST request failed: {e}")

	def _test_blind_sqli_form_param(self, url, method, param, inputs, findings):
		"""Test for blind SQLi using OAST callbacks on form parameters"""
		if not self.oast_collaborator:
			return
		
		# Skip CSRF token fields
		if 'csrf' in param.lower():
			return
			
		# Generate OAST payloads for different database types
		oast_payloads = self.oast_collaborator.generate_sqli_payloads()
		
		for payload_info in oast_payloads:
			payload = payload_info['payload']
			callback_id = payload_info['callback_id']
			data = {p: (payload if p == param else 'test') for p in inputs}
			self.log(f"[OAST-{method.upper()}] Testing blind SQLi {url} param={param} payload={payload}")
			
			try:
				# Send the request with OAST payload
				if method == 'post':
					resp = self.session.post(url, data=data, timeout=10)
				else:
					resp = self.session.get(url, params=data, timeout=10)
				
				# Wait briefly for callback
				import time
				time.sleep(3)
				
				# Check if we received a callback
				if self.oast_collaborator.check_callback(callback_id):
					self.log(f"BLIND SQLi detected via OAST: {url} param={param}")
					findings.append(Vulnerability(
						vulnerability_type="Blind SQLi (OAST)",
						url=url,
						parameter=param,
						payload=payload,
						evidence="OAST callback received indicating successful blind SQLi execution",
						confidence="High"
					))
					break  # Found vulnerability, no need to test other DB types
					
			except Exception as e:
				self.log(f"OAST request failed: {e}")
