import re
from vulnerability import Vulnerability


class CryptographicFailuresScanner:
    """Heuristic cryptographic failures scanner."""

    def __init__(self, session, verbose=False, oast_collaborator=None):
        self.session = session
        self.verbose = verbose
        self.oast_collaborator = oast_collaborator

    def log(self, msg):
        if self.verbose:
            print(f"[CryptoFailures] {msg}")

    def scan(self, attack_surface):
        findings = []
        checked = set()
        for url, _ in attack_surface.get('urls', []):
            base = url.split('#')[0]
            if base in checked:
                continue
            checked.add(base)
            try:
                resp = self.session.get(base, timeout=8)
                if base.startswith('http://'):
                    findings.append(Vulnerability(
                        vulnerability_type="cryptographic_failures",
                        url=base,
                        parameter="protocol",
                        payload="",
                        evidence="Application served over HTTP (no transport encryption)."
                    ))
                elif base.startswith('https://') and 'Strict-Transport-Security' not in resp.headers:
                    findings.append(Vulnerability(
                        vulnerability_type="cryptographic_failures",
                        url=base,
                        parameter="hsts",
                        payload="",
                        evidence="Missing Strict-Transport-Security header."
                    ))
                if base.startswith('https://') and (re.search(r'src=["\']http://', resp.text, re.IGNORECASE) or re.search(r'href=["\']http://', resp.text, re.IGNORECASE)):
                    findings.append(Vulnerability(
                        vulnerability_type="cryptographic_failures",
                        url=base,
                        parameter="mixed_content",
                        payload="",
                        evidence="HTTPS page loads insecure (HTTP) resources."
                    ))
                if re.search(r'md5\(|sha1\(', resp.text, re.IGNORECASE):
                    findings.append(Vulnerability(
                        vulnerability_type="cryptographic_failures",
                        url=base,
                        parameter="weak_hash",
                        payload="",
                        evidence="Reference to weak hash (MD5/SHA1)."
                    ))
            except Exception:
                pass
        return findings
