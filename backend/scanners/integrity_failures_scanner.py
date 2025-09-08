import re
from vulnerability import Vulnerability


class IntegrityFailuresScanner:
    """Software & Data Integrity Failures scanner."""

    EXTERNAL_SCRIPT_PATTERN = re.compile(r'<script[^>]+src=["\'](https?://[^"\']+)["\'][^>]*>', re.IGNORECASE)
    SENSITIVE_PATHS = [
        '/.git/HEAD', '/.svn/entries', '/.hg/', '/composer.lock', '/package-lock.json', '/yarn.lock',
        '/pnpm-lock.yaml', '/Gemfile.lock', '/.github/workflows/', '/docker-compose.yml', '/Dockerfile'
    ]

    def __init__(self, session, verbose=False, oast_collaborator=None):
        self.session = session
        self.verbose = verbose
        self.oast_collaborator = oast_collaborator

    def log(self, msg):
        if self.verbose:
            print(f"[IntegrityFailures] {msg}")

    def scan(self, attack_surface):
        findings = []
        seen_pages = set()
        for url, _ in attack_surface.get('urls', []):
            base = url.split('#')[0]
            if base in seen_pages:
                continue
            seen_pages.add(base)
            try:
                resp = self.session.get(base, timeout=8)
                content = resp.text
                for match in self.EXTERNAL_SCRIPT_PATTERN.finditer(content):
                    script_url = match.group(1)
                    tag_text = match.group(0)
                    if 'integrity=' not in tag_text.lower() and any(d in script_url for d in ['cdn', 'cloudflare', 'unpkg', 'jsdelivr', 'googleapis']):
                        findings.append(Vulnerability(
                            vulnerability_type="integrity_failures",
                            url=base,
                            parameter="script",
                            payload="",
                            evidence=f"External script without Subresource Integrity: {script_url}"
                        ))
            except Exception:
                pass
        base_hosts = set('/'.join(u.split('/')[:3]) for u, _ in attack_surface.get('urls', []))
        for base in base_hosts:
            for path in self.SENSITIVE_PATHS:
                test_url = base.rstrip('/') + path
                try:
                    r = self.session.get(test_url, timeout=6)
                    if r.status_code == 200 and len(r.text) > 20:
                        findings.append(Vulnerability(
                            vulnerability_type="integrity_failures",
                            url=test_url,
                            parameter="file",
                            payload="",
                            evidence=f"Accessible build/dependency file: {path}"
                        ))
                except Exception:
                    pass
        return findings
