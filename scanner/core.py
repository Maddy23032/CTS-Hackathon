import requests
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from urllib.parse import urljoin

from .xss import test_xss
from .sql_injection import test_sqli
from .csrf import check_csrf
from .report import generate_html_report

class WebSecurityScanner:
    def __init__(self, base_url, max_depth=2, max_workers=5, login_url=None, username=None, password=None):
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_workers = max_workers
        self.login_url = login_url
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.visited_urls = set()
        self.vulnerabilities = []

        if self.login_url and self.username and self.password:
            self.login()

    def login(self):
        # Implement authentication logic if needed
        pass

    def crawl(self, url, depth=0):
        if depth > self.max_depth or url in self.visited_urls:
            return
        try:
            self.visited_urls.add(url)
            response = self.session.get(url)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, "html.parser")

            for link in soup.find_all("a", href=True):
                next_url = urljoin(url, link["href"])
                if next_url.startswith(self.base_url):
                    self.crawl(next_url, depth + 1)
        except Exception as e:
            print(f"Error crawling {url}: {e}")

    def scan_url(self, url):
        try:
            response = self.session.get(url)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")
            print(f"Found {len(forms)} forms on {url}")

            for i, form in enumerate(forms, start=1):
                method = (form.get("method") or "get").lower()

                results = [
                    check_csrf(form, method),
                    test_xss(self.session, url, form),
                    test_sqli(self.session, url, form)
                ]

                for result in results:
                    if result and result.get("vulnerable"):
                        self.vulnerabilities.append({
                            "url": url,
                            "form_number": i,
                            **result,
                        })
        except Exception as e:
            print(f"Error scanning {url}: {e}")

    def scan(self):
        print(f"Starting scan of {len(self.visited_urls)} URLs with {self.max_workers} workers...")
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.scan_url, url) for url in self.visited_urls]
            for future in futures:
                future.result()

    def generate_report(self, filename="report.html"):
        print(f"Generating report: {filename}")
        generate_html_report(self.base_url, self.vulnerabilities, filename)
