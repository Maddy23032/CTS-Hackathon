import re
from vulnerability import Vulnerability


class AuthenticationFailuresScanner:
    """Identification & Authentication Failures scanner (heuristic)."""

    def __init__(self, session, verbose=False, oast_collaborator=None):
        self.session = session
        self.verbose = verbose
        self.oast_collaborator = oast_collaborator

    def log(self, msg):
        if self.verbose:
            print(f"[AuthFailures] {msg}")

    def scan(self, attack_surface):
        findings = []
        for form in attack_surface.get('forms', []):
            try:
                if not isinstance(form, dict):
                    continue
                action = form.get('action') or form.get('url') or 'N/A'
                raw_inputs = form.get('inputs', [])
                norm = []
                for i in raw_inputs:
                    if isinstance(i, dict):
                        norm.append(i)
                    else:
                        name = str(i); inferred = 'password' if 'pass' in name.lower() else 'text'
                        norm.append({'name': name, 'type': inferred, 'attributes': {}})
                if not any(i.get('type') == 'password' for i in norm):
                    continue
                token_present = any(
                    i.get('type') == 'hidden' and re.search(r'(csrf|token|authenticity)', (i.get('name') or ''), re.IGNORECASE)
                    for i in norm
                ) or bool(form.get('csrf_tokens'))
                if not token_present:
                    findings.append(Vulnerability(
                        vulnerability_type="authentication_failures",
                        url=action,
                        parameter="form",
                        payload="",
                        evidence="Login form without apparent anti-CSRF token (heuristic)."
                    ))
                pw_fields = [i for i in norm if i.get('type') == 'password']
                autocomplete_off = any((i.get('attributes') or {}).get('autocomplete', '').lower() == 'off' for i in pw_fields)
                if pw_fields and not autocomplete_off:
                    findings.append(Vulnerability(
                        vulnerability_type="authentication_failures",
                        url=action,
                        parameter="password_field",
                        payload="",
                        evidence="Password field missing autocomplete=off."
                    ))
            except Exception:
                pass
        # Cookie flags
        seen = set()
        for url, _ in attack_surface.get('urls', []):
            base = url.split('#')[0]
            if base in seen:
                continue
            seen.add(base)
            try:
                resp = self.session.get(base, timeout=8)
                cookies = resp.headers.get('Set-Cookie', '')
                if cookies:
                    for cookie in cookies.split(','):
                        if '=' not in cookie:
                            continue
                        c = cookie.lower()
                        if ('session' in c or 'auth' in c) and ('httponly' not in c or 'secure' not in c):
                            missing = []
                            if 'httponly' not in c: missing.append('HttpOnly')
                            if 'secure' not in c: missing.append('Secure')
                            findings.append(Vulnerability(
                                vulnerability_type="authentication_failures",
                                url=base,
                                parameter="cookie",
                                payload="",
                                evidence=f"Session/auth cookie missing flags: {', '.join(missing)}"
                            ))
            except Exception:
                pass
        return findings
