import re
import requests
from vulnerability import Vulnerability


class BrokenAccessControlScanner:
    """Heuristic Broken Access Control scanner (subset adapted from CLI)."""

    COMMON_ADMIN_PATHS = [
        "/admin", "/administrator", "/admin/login", "/admin/dashboard", "/admin/index.php",
        "/adminpanel", "/cpanel", "/manage", "/manager", "/user/admin", "/dashboard"
    ]
    IDOR_PARAM_NAMES = ["id", "user", "uid", "account", "profile", "order", "invoice", "doc", "record"]

    def __init__(self, session, verbose=False, oast_collaborator=None):
        self.session = session
        self.verbose = verbose
        self.oast_collaborator = oast_collaborator

    def log(self, msg):
        if self.verbose:
            print(f"[BrokenAccessControl] {msg}")

    def scan(self, attack_surface):
        findings = []
        base_urls = set()
        for url, _ in attack_surface.get('urls', []):
            if '://' in url:
                base_urls.add('/'.join(url.split('/')[:3]))
        for base in base_urls:
            findings.extend(self._check_admin_paths(base))
        for url, params in attack_surface.get('urls', []):
            findings.extend(self._check_idor(url, params))
        return findings

    def _check_admin_paths(self, base_url):
        findings = []
        s = requests.Session()
        for path in self.COMMON_ADMIN_PATHS:
            test_url = base_url.rstrip('/') + path
            try:
                r = s.get(test_url, timeout=6, allow_redirects=True)
                if r.status_code == 200 and re.search(r"admin|dashboard|manage users|control panel", r.text, re.IGNORECASE):
                    findings.append(Vulnerability(
                        vulnerability_type="broken_access_control",
                        url=test_url,
                        parameter="path",
                        payload="",
                        evidence="Unauthenticated access to potential admin area (status 200, keywords found)."
                    ))
            except Exception:
                pass
        return findings

    def _check_idor(self, url, param_names):
        from urllib.parse import urlparse, parse_qs, urlencode
        findings = []
        if not param_names:
            return findings
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            baseline = self.session.get(url, timeout=6)
            orig_len = len(baseline.text)
        except Exception:
            return findings
        for name in param_names:
            try:
                vals = qs.get(name)
                if not vals:
                    continue
                v = vals[0]
                if name.lower() not in self.IDOR_PARAM_NAMES or not v.isdigit():
                    continue
                int_val = int(v)
                for alt in [str(int_val + 1), str(max(int_val - 1, 0))]:
                    new_qs = qs.copy(); new_qs[name] = [alt]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(new_qs, doseq=True)}"
                    try:
                        r = self.session.get(test_url, timeout=6)
                        if r.status_code == 200:
                            diff = abs(len(r.text) - orig_len)
                            if orig_len and diff > 0.15 * orig_len:
                                findings.append(Vulnerability(
                                    vulnerability_type="broken_access_control",
                                    url=test_url,
                                    parameter=name,
                                    payload=f"IDOR test -> {alt}",
                                    evidence=f"Content length changed from {orig_len} to {len(r.text)} for {name}; potential IDOR."
                                ))
                                break
                    except Exception:
                        pass
            except Exception:
                pass
        return findings
