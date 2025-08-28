import re
from urllib.parse import urljoin
from .payloads import PAYLOADS
from .remediation import generate_remediation
import random

# Regex patterns for SQL error detection
SQL_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning: mysql", re.I),
    re.compile(r"mysql_fetch", re.I),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"syntax error", re.I),
    re.compile(r"sqlite3\.OperationalError", re.I),
    re.compile(r"pg_query\(\) \[: syntax error", re.I),
    re.compile(r"mysql_num_rows\(\)", re.I),
    re.compile(r"SQLSTATE\[\d+\]", re.I),
    re.compile(r"native client", re.I),
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
    re.compile(r"DB2 SQL error", re.I),
    re.compile(r"mysqlnd", re.I),
]

def fuzz_payload(base_payload):
    mutations = [
        lambda x: x + "' OR '1'='1",
        lambda x: x + "<script>alert(1)</script>",
        lambda x: x.replace(" ", "%20"),
        lambda x: x[::-1],  # reverse string
        lambda x: x.upper(),
        lambda x: ''.join(random.sample(x, len(x))) if len(x) > 1 else x,  # shuffle chars
    ]
    mutation = random.choice(mutations)
    return mutation(base_payload)

def contains_sql_error(response_text):
    for pattern in SQL_ERROR_PATTERNS:
        if pattern.search(response_text):
            return True
    return False

def test_sqli(session, url, form):
    action = form.get("action")
    method = (form.get("method") or "get").lower()
    inputs = form.find_all("input")

    for base_payload in PAYLOADS["sqli"]:
        vulnerability_hits = 0
        attempts = 3  # number of fuzz attempts per payload

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

                if contains_sql_error(resp.text):
                    vulnerability_hits += 1
            except Exception as e:
                print(f"Exception during SQLi test: {e}")
                continue

        if vulnerability_hits >= (attempts // 2 + 1):
            details = {"payload": base_payload, "field_name": last_name or "unknown"}
            return {
                "vulnerability_type": "SQL Injection",
                "vulnerable": True,
                "message": f"Detected SQL Injection vulnerability with fuzzed payloads around: {base_payload}",
                "remediation": generate_remediation("SQL Injection", details),
            }

    return {
        "vulnerability_type": "SQL Injection",
        "vulnerable": False,
        "message": "",
        "remediation": "",
    }
