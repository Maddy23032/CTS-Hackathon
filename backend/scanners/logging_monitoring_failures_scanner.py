import re
from vulnerability import Vulnerability


class LoggingMonitoringFailuresScanner:
    """Security Logging & Monitoring Failures scanner."""

    ERROR_TRIGGER_PATHS = ["/__VulnScan_404_test__", "/__VulnScan_error_test__/12345"]

    def __init__(self, session, verbose=False, oast_collaborator=None):
        self.session = session
        self.verbose = verbose
        self.oast_collaborator = oast_collaborator

    def log(self, msg):
        if self.verbose:
            print(f"[LogMonFailures] {msg}")

    def scan(self, attack_surface):
        findings = []
        base_hosts = set('/'.join(u.split('/')[:3]) for u, _ in attack_surface.get('urls', []))
        for base in base_hosts:
            for path in self.ERROR_TRIGGER_PATHS:
                test_url = base.rstrip('/') + path
                try:
                    r = self.session.get(test_url, timeout=6)
                    body = r.text[:1000]
                    if r.status_code >= 500 and re.search(r'(Exception|Traceback|Stack trace|Warning: )', body, re.IGNORECASE):
                        findings.append(Vulnerability(
                            vulnerability_type="logging_monitoring_failures",
                            url=test_url,
                            parameter="error_handling",
                            payload="",
                            evidence=f"Verbose server error exposes stack trace (status {r.status_code})."
                        ))
                    elif r.status_code == 404 and re.search(r'(Apache Tomcat|nginx|IIS|Express)', body, re.IGNORECASE):
                        findings.append(Vulnerability(
                            vulnerability_type="logging_monitoring_failures",
                            url=test_url,
                            parameter="error_page",
                            payload="",
                            evidence="Default error page reveals stack; custom handling absent."
                        ))
                except Exception:
                    pass
        return findings
