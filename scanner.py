import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
from concurrent.futures import ThreadPoolExecutor

REMEDIATION_TIPS = {
    "XSS": "Sanitize user inputs and encode output to prevent script injection.",
    "SQL Injection": "Use parameterized queries or prepared statements to safely handle database inputs.",
    "CSRF": "Implement anti-CSRF tokens on all POST forms to prevent unauthorized requests."
}

class WebSecurityScanner:
    def __init__(self, base_url, max_depth=2, max_workers=5, login_url=None, username=None, password=None):
        self.base_url = base_url
        self.max_depth = max_depth
        self.visited = set()
        self.vulnerabilities = []
        self.max_workers = max_workers
        self.session = requests.Session()
        self.login_url = login_url
        self.username = username
        self.password = password

        if self.login_url and self.username and self.password:
            self.login()

    def login(self):
        print(f"Logging in at {self.login_url} with username '{self.username}'")
        try:
            res = self.session.get(self.login_url)
            res.raise_for_status()
            soup = BeautifulSoup(res.text, "html.parser")
            login_data = {  # Adjust keys according to actual form input names
                "username": self.username,
                "password": self.password
            }
            # Include hidden inputs like CSRF tokens if present
            for hidden_input in soup.find_all("input", type="hidden"):
                name = hidden_input.get("name")
                value = hidden_input.get("value", "")
                if name and name not in login_data:
                    login_data[name] = value

            post_res = self.session.post(self.login_url, data=login_data)
            post_res.raise_for_status()
            if "logout" in post_res.text.lower() or post_res.status_code == 200:
                print("Login successful.")
            else:
                print("Login completed but unable to verify success.")
        except Exception as e:
            print(f"Login failed: {e}")

    def is_valid(self, url):
        parsed_base = urlparse(self.base_url)
        parsed = urlparse(url)
        return (parsed.scheme in ["http", "https"]) and (parsed.netloc == parsed_base.netloc)

    def crawl(self, url, depth=0):
        if depth > self.max_depth or url in self.visited:
            return
        try:
            print(f"Crawling {url} at depth {depth}")
            response = self.session.get(url)
            response.raise_for_status()
            self.visited.add(url)

            soup = BeautifulSoup(response.text, "html.parser")
            links = [urljoin(url, a["href"]) for a in soup.find_all("a", href=True)]
            for link in links:
                if self.is_valid(link) and link not in self.visited:
                    self.crawl(link, depth + 1)

            time.sleep(0.5)
        except Exception as e:
            print(f"Failed to crawl {url}: {e}")

    def scan_url(self, url):
        print(f"\nScanning {url} ...")
        try:
            response = self.session.get(url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
        except Exception as e:
            print(f"Error fetching {url}: {e}")
            return

        forms = soup.find_all("form")
        print(f"Found {len(forms)} forms on {url}")

        xss_payload = "<script>alert('XSS')</script>"
        sqli_payload = "' OR '1'='1"

        for i, form in enumerate(forms):
            print(f"\nForm #{i + 1}")

            method = (form.get("method") or "get").lower()

            csrf_vuln = self.check_csrf(form, method, i + 1)
            xss_vuln = self.test_form(url, form, xss_payload, i + 1, "XSS")
            sqli_vuln = self.test_form(url, form, sqli_payload, i + 1, "SQL Injection")

            self.vulnerabilities.extend([csrf_vuln, xss_vuln, sqli_vuln])

    def check_csrf(self, form, method, form_num):
        inputs = form.find_all("input")
        has_token = any(
            inp.get("type") == "hidden" and
            ("csrf" in (inp.get("name") or "").lower() or "token" in (inp.get("name") or "").lower())
            for inp in inputs
        )
        if method == "post" and not has_token:
            print(f" - WARNING: Form {form_num} missing CSRF token (possible vulnerability)")
            return {
                "form_number": form_num,
                "vulnerability_type": "CSRF",
                "vulnerable": True,
                "message": "Missing CSRF token",
                "remediation": REMEDIATION_TIPS["CSRF"]
            }
        else:
            print(f" - Form {form_num} has CSRF protection or is non-POST")
            return {
                "form_number": form_num,
                "vulnerability_type": "CSRF",
                "vulnerable": False,
                "message": "",
                "remediation": ""
            }

    def test_form(self, url, form, payload, form_num, vuln_type):
        action = form.get("action")
        method = (form.get("method") or "get").lower()
        inputs = form.find_all("input")
        data = {inp.get("name"): payload for inp in inputs if inp.get("name")}

        target_url = urljoin(url, action) if action else url
        try:
            if method == "post":
                resp = self.session.post(target_url, data=data)
            else:
                resp = self.session.get(target_url, params=data)
            if payload in resp.text:
                print(f" - Possible {vuln_type} vulnerability detected!")
                return {
                    "form_number": form_num,
                    "vulnerability_type": vuln_type,
                    "vulnerable": True,
                    "message": "Payload reflected",
                    "remediation": REMEDIATION_TIPS.get(vuln_type, "")
                }
            else:
                print(f" - No {vuln_type} vulnerability detected.")
                return {
                    "form_number": form_num,
                    "vulnerability_type": vuln_type,
                    "vulnerable": False,
                    "message": "",
                    "remediation": ""
                }
        except Exception as e:
            print(f"Error testing form {form_num} for {vuln_type} on {target_url}: {e}")
            return {
                "form_number": form_num,
                "vulnerability_type": vuln_type,
                "vulnerable": False,
                "message": "Error during testing",
                "remediation": ""
            }

    def generate_html_report(self, filename="report.html"):
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Scan Report for {self.base_url}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .vuln {{ color: red; font-weight: bold; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .remediation {{ font-style: italic; background-color: #f9f9f9; }}
            </style>
        </head>
        <body>
            <h1>Scan Report for {self.base_url}</h1>
            <table>
                <tr>
                    <th>Form #</th>
                    <th>Vulnerability Type</th>
                    <th>Details</th>
                </tr>
        """

        for vuln in self.vulnerabilities:
            color = "vuln" if vuln["vulnerable"] else ""
            status = "Yes" if vuln["vulnerable"] else "No"
            detail_msg = vuln.get("message", "")
            remediation_msg = vuln.get("remediation", "")
            form_num = vuln.get("form_number", "")
            vuln_type = vuln.get("vulnerability_type", "")

            html_content += f"""
                <tr>
                    <td>{form_num}</td>
                    <td>{vuln_type}</td>
                    <td class="{color}">{status} {detail_msg}</td>
                </tr>
                <tr class="remediation">
                    <td colspan="3">Remediation: {remediation_msg if remediation_msg else "N/A"}</td>
                </tr>
            """

        html_content += """
            </table>
        </body>
        </html>
        """

        with open(filename, "w") as f:
            f.write(html_content)
        print(f"\nHTML report saved as {filename}")

def main():
    parser = argparse.ArgumentParser(description="Authenticated Web Vulnerability Scanner")
    parser.add_argument("url", help="Base URL to start crawling")
    parser.add_argument("--depth", type=int, default=2, help="Max crawl depth")
    parser.add_argument("--workers", type=int, default=5, help="Max concurrent workers")
    parser.add_argument("--login-url", help="Login form URL for authentication")
    parser.add_argument("--username", help="Username for login")
    parser.add_argument("--password", help="Password for login")
    args = parser.parse_args()

    scanner = WebSecurityScanner(
        base_url=args.url,
        max_depth=args.depth,
        max_workers=args.workers,
        login_url=args.login_url,
        username=args.username,
        password=args.password
    )
    scanner.crawl(args.url)

    print(f"\nCrawled {len(scanner.visited)} pages. Starting concurrent scanning...\n")

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(scanner.scan_url, url) for url in scanner.visited]
        for future in futures:
            future.result()

    print("\nConcurrent scan complete.")
    scanner.generate_html_report()

if __name__ == "__main__":
    main()
