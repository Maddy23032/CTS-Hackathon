from vulnerability import Vulnerability
from bs4 import BeautifulSoup

class CSRFScanner:
	TOKEN_NAMES = [
		'csrf', 'token', 'xsrf', 'authenticity_token', 'requesttoken', 'csrftoken', 'csrfmiddlewaretoken', '__RequestVerificationToken'
	]

	def __init__(self, session, verbose=False):
		self.session = session
		self.verbose = verbose

	def log(self, msg):
		if self.verbose:
			print(f"[CSRFScanner] {msg}")

	def scan(self, attack_surface):
		findings = []
		# Check POST forms for anti-CSRF tokens
		for form in attack_surface.get('forms', []):
			url = form['url']
			method = form['method']
			inputs = form['inputs']
			if method == 'post':
				try:
					resp = self.session.get(url, timeout=10)
					soup = BeautifulSoup(resp.text, 'html.parser')
					form_tag = soup.find('form')
					if form_tag:
						hidden_inputs = form_tag.find_all('input', {'type': 'hidden'})
						token_found = False
						for inp in hidden_inputs:
							name = inp.get('name', '').lower()
							if any(token in name for token in self.TOKEN_NAMES):
								token_found = True
								break
						if not token_found:
							findings.append(Vulnerability(
								vulnerability_type="csrf",
								url=url,
								parameter=','.join(inputs),
								payload="",
								evidence="No anti-CSRF token found in POST form."
							))
							self.log(f"CSRF risk: {url} (no anti-CSRF token)")
				except Exception as e:
					self.log(f"Request failed: {e}")
		# Check SameSite attribute in cookies
		for url, _ in attack_surface.get('urls', []):
			try:
				resp = self.session.get(url, timeout=10)
				set_cookie = resp.headers.get('Set-Cookie', '')
				if set_cookie:
					cookies = set_cookie.split(',')
					for cookie in cookies:
						if 'samesite' not in cookie.lower():
							findings.append(Vulnerability(
								vulnerability_type="csrf",
								url=url,
								parameter="cookie",
								payload="",
								evidence=f"Session cookie missing SameSite attribute: {cookie.strip()}"
							))
							self.log(f"CSRF risk: {url} (cookie missing SameSite)")
			except Exception as e:
				self.log(f"Request failed: {e}")
		return findings
