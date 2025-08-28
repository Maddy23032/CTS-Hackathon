import re
from urllib.parse import urljoin
from .payloads import PAYLOADS
from .remediation import generate_remediation
import random

# Common regex patterns for XSS detection
XSS_INDICATORS = [
    re.compile(r"<script>alert\(.*?\)</script>", re.I),
    re.compile(r"onerror\s*=\s*alert\(.*?\)", re.I),
    re.compile(r"javascript:", re.I),
    re.compile(r"<svg/onload=alert\(.*?\)>", re.I),
    re.compile(r"<iframe src=.*?javascript:alert\(.*?\).*?></iframe>", re.I),
]

def fuzz_payload(base_payload):
    mutations = [
        lambda x: x + "<script>alert(1)</script>",
        lambda x: x.replace("<", "&lt;").replace(">", "&gt;"),  # HTML encode
        lambda x: x[::-1],  # reversed string
        lambda x: x.upper(),
        lambda x: ''.join(random.sample(x, len(x))) if len(x) > 1 else x,  # shuffle chars
    ]
    mutation = random.choice(mutations)
    return mutation(base_payload)

def contains_xss_indicator(response_text, base_payload):
    if base_payload in response_text:
        return True
    for pattern in XSS_INDICATORS:
        if pattern.search(response_text):
            return True
    return False

def test_xss(session, url, form):
    action = form.get("action")
    method = (form.get("method") or "get").lower()
    inputs = form.find_all("input")

    for base_payload in PAYLOADS["xss"]:
        vulnerability_hits = 0
        attempts = 3

        for _ in range(attempts):
            payload = fuzz_payload(base_payload)
            data = {}
            last_name = None
            for inp in inputs:
                name = inp.get("name")
                if name:
                    data[name] = payload
                    last_name = name

            target_url = urljoin(url, action) if action else url

            try:
                if method == "post":
                    resp = session.post(target_url, data=data)
                else:
                    resp = session.get(target_url, params=data)

                if contains_xss_indicator(resp.text, base_payload):
                    vulnerability_hits += 1
            except Exception:
                continue

        if vulnerability_hits >= (attempts // 2 + 1):
            details = {"payload": base_payload, "field_name": last_name or "unknown"}
            return {
                "vulnerability_type": "XSS",
                "vulnerable": True,
                "message": f"Reflected XSS vulnerability confirmed with fuzzed payloads around: {base_payload}",
                "remediation": generate_remediation("XSS", details),
            }

    return {
        "vulnerability_type": "XSS",
        "vulnerable": False,
        "message": "",
        "remediation": "",
    }
