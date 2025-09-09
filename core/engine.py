import time
import hashlib
import re
from collections import deque
from urllib.parse import urlparse, urljoin, parse_qs
import requests
from bs4 import BeautifulSoup
import io
import concurrent.futures
import threading

class DiscoveryEngine:
    """
    The final, correct version. Multi-threaded for speed and comprehensive
    in its data gathering and reporting.
    """
    def __init__(self, base_url, max_depth=2, num_threads=10, login_url=None, login_data=None):
        self.base_url = base_url
        self.base_netloc = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.num_threads = num_threads
        
        self.login_url = login_url
        self.login_data = login_data

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityMapper/5.0 (Multi-Threaded)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        })

        self.urls_ever_queued = {self.base_url}
        self.discovered_states = {}
        self.tech_profile = set()
        self.lock = threading.Lock()

    def _perform_login(self):
        """Attempts to authenticate to the website before starting the scan."""
        if not self.login_url or not self.login_data:
            return
        print(f"\n[AUTH] Attempting login to {self.login_url}...")
        try:
            data_dict = dict(item.split('=') for item in self.login_data.split('&'))
            res = self.session.post(self.login_url, data=data_dict, allow_redirects=True)
            res.raise_for_status()
            if self.session.cookies:
                print("[AUTH] Login successful. Session cookies captured.")
            else:
                print("[AUTH] Login may have failed. No session cookies were set.")
        except Exception as e:
            print(f"[AUTH] Login failed with an error: {e}")

    def _process_url(self, url, depth):
        """This function is executed by each thread."""
        try:
            # print(f"[CRAWLING] Depth: {depth} | URL: {url}") # This can be noisy, optional
            response = self.session.get(url, timeout=10, allow_redirects=True)
            response.raise_for_status()
        except requests.RequestException:
            return []

        if 'text/html' not in response.headers.get('Content-Type', ''):
            return []

        soup = BeautifulSoup(response.text, 'html.parser')
        fingerprint = self._get_page_fingerprint(soup)

        new_links_to_process = []

        with self.lock:
            if not fingerprint or fingerprint in self.discovered_states:
                return []
            
            self._fingerprint_technologies(response)
            # --- CRITICAL: Call the NEW comprehensive function ---
            state_data = {
                "url": url,
                "input_vectors": self._extract_all_input_vectors(soup, response),
                "request_template": self._generate_request_template(response)
            }
            self.discovered_states[fingerprint] = state_data
            print(f"[DISCOVERY] New unique state found at: {url} (Fingerprint: {fingerprint[:12]}...)")


        for link_tag in soup.find_all(['a', 'link'], href=True):
            href = link_tag.get('href')
            if not href or href.strip().startswith(('javascript:', 'mailto:')): continue
            absolute_url = urljoin(url, href.strip())
            
            with self.lock:
                if self._is_valid_for_queueing(absolute_url):
                    if absolute_url not in self.urls_ever_queued:
                        self.urls_ever_queued.add(absolute_url)
                        if depth + 1 <= self.max_depth:
                            new_links_to_process.append((absolute_url, depth + 1))
        
        return new_links_to_process
    
    def run_discovery(self):
        start_time = time.time()
        self._perform_login()
        print(f"\n[INFO] Starting discovery with {self.num_threads} threads.")
        
        urls_to_process = deque([(self.base_url, 0)])

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            while urls_to_process:
                future_to_url = {executor.submit(self._process_url, url, depth): url for url, depth in urls_to_process}
                urls_to_process.clear()

                for future in concurrent.futures.as_completed(future_to_url):
                    try:
                        new_links = future.result()
                        if new_links:
                            for link, depth in new_links:
                                urls_to_process.append((link, depth))
                    except Exception as exc:
                        print(f"'{future_to_url[future]}' generated an exception: {exc}")

        duration = time.time() - start_time
        self._print_final_report(duration)
        return self._format_text_report(duration)

    # --- THIS IS THE NEW, COMPREHENSIVE FUNCTION YOU NEEDED ---
    def _extract_all_input_vectors(self, soup, response):
        vectors = {
            "url_params": [], "forms": [], "cookies": [], "headers": []
        }
        # 1. URL Parameters
        query = urlparse(response.url).query
        if query:
            vectors['url_params'] = [{"name": k} for k in parse_qs(query).keys()]
        # 2. HTML Forms
        for form in soup.find_all('form'):
            form_details = {"action": urljoin(response.url, form.get('action')),"method": form.get('method', 'get').lower(),"fields": [{"name": i.get('name'), "type": i.get('type', 'text')} for i in form.find_all(['input', 'textarea', 'select'])]}
            vectors['forms'].append(form_details)
        # 3. Request Cookies
        if 'Cookie' in response.request.headers:
            vectors['cookies'] = [{"name": c.split('=')[0].strip()} for c in response.request.headers['Cookie'].split(';')]
        # 4. "Interesting" Custom/Request Headers
        interesting_headers = [
            'Authorization', 'X-Forwarded-For', 'X-Client-IP', 
            'X-Real-IP', 'Referer', 'X-Api-Key', 'Api-Key', 'X-CSRF-Token'
        ]
        vectors['headers'] = [{"name": h} for h in response.request.headers if h in interesting_headers]
        return vectors

    def _get_page_fingerprint(self, soup):
        structural_elements = []
        forms = soup.find_all('form')
        if forms:
            for form in sorted(forms, key=lambda f: f.get('action', '')):
                action = form.get('action', ''); method = form.get('method', 'get').lower()
                structural_elements.append(f"form:{action}:{method}")
        else:
            title = soup.find('title')
            if title:
                structural_elements.append(f"title:{title.get_text()}")
        struct_fingerprint = hashlib.sha256('|'.join(structural_elements).encode('utf-8', 'ignore')).hexdigest()
        text_content = re.sub(r'\s+', ' ', soup.get_text(" ", strip=True))
        content_hash = hashlib.sha256(text_content.encode('utf-8', 'ignore')).hexdigest()
        return f"{struct_fingerprint}-{content_hash}"

    def _print_final_report(self, duration):
        print("\n" + "="*50)
        print("          Attack Surface Map")
        print("="*50)
        print(f"Time Taken: {duration:.2f} seconds")
        print(f"Total Unique Pages Discovered: {len(self.discovered_states)}")
        print("-"*50)
        discovered_urls = sorted([state['url'] for state in self.discovered_states.values()])
        for i, url in enumerate(discovered_urls, 1):
            print(f"{i:02d}: {url}")
        print("="*50)

    # --- THIS IS THE NEW, COMPREHENSIVE REPORTING FUNCTION ---
    def _format_text_report(self, duration):
        report = io.StringIO()
        report.write("==================================================\n")
        report.write("        Comprehensive Attack Surface Report\n")
        report.write("==================================================\n\n")
        report.write("[+] SUMMARY\n")
        report.write("--------------------------------------------------\n")
        report.write(f"Target URL: {self.base_url}\n")
        report.write(f"Time Taken: {duration:.2f} seconds\n")
        report.write(f"Total Unique States Found: {len(self.discovered_states)}\n")
        if self.tech_profile: report.write(f"Technologies Identified: {', '.join(sorted(list(self.tech_profile)))}\n")
        session_cookies = {c.name: c.value for c in self.session.cookies}
        if session_cookies:
            report.write("Session Cookies Established:\n")
            for name, value in session_cookies.items(): report.write(f"  - {name}: {value}\n")
        report.write("\n")
        report.write("[+] DISCOVERED APPLICATION STATES\n")
        report.write("--------------------------------------------------\n\n")
        sorted_states = sorted(self.discovered_states.values(), key=lambda x: x['url'])
        for i, state in enumerate(sorted_states, 1):
            report.write(f"--- State #{i:02d} ---\n")
            report.write(f"URL: {state['url']}\n\n")
            report.write("  [Comprehensive Input Vectors]\n")
            vectors = state['input_vectors']
            all_vectors_empty = True
            if vectors['url_params']:
                all_vectors_empty = False
                report.write("    - URL Parameters:\n")
                for p in vectors['url_params']: report.write(f"      - Name: {p['name']}\n")
            if vectors['forms']:
                all_vectors_empty = False
                for form_num, form in enumerate(vectors['forms'], 1):
                    report.write(f"    - Form #{form_num}:\n")
                    report.write(f"      Action: {form['action']}\n")
                    report.write(f"      Method: {form['method'].upper()}\n")
                    if form['fields']:
                        report.write(f"      Fields:\n")
                        for field in form['fields']: report.write(f"        - Name: {field.get('name', 'N/A')}, Type: {field.get('type', 'N/A')}\n")
            if vectors['cookies']:
                all_vectors_empty = False
                report.write("    - Request Cookies:\n")
                for c in vectors['cookies']: report.write(f"      - Name: {c['name']}\n")
            if vectors['headers']:
                 all_vectors_empty = False
                 report.write("    - Interesting Request Headers:\n")
                 for h in vectors['headers']: report.write(f"      - Name: {h['name']}\n")
            if all_vectors_empty:
                report.write("    - No primary input vectors discovered for this state.\n")
            report.write("\n  [Original HTTP Request Template]\n")
            report.write("    " + state['request_template'].replace('\n', '\n    ') + "\n\n")
        return report.getvalue()

    def _fingerprint_technologies(self, response):
        headers = {k.lower(): v for k, v in response.headers.items()}
        if 'server' in headers: self.tech_profile.add(f"server:{headers['server']}")
        if 'x-powered-by' in headers: self.tech_profile.add(f"powered-by:{headers['x-powered-by']}")
        if 'x-aspnet-version' in headers: self.tech_profile.add(f"tech:ASP.NET {headers['x-aspnet-version']}")
    def _generate_request_template(self, response):
        req = response.request
        path_part = urlparse(req.url).path
        query_part = urlparse(req.url).query
        full_path = f"{path_part}?{query_part}" if query_part else path_part
        template = f"{req.method} {full_path} HTTP/1.1\nHost: {urlparse(req.url).netloc}\n"
        template += "\n".join(f"{k}: {v}" for k, v in req.headers.items())
        return template
    def _is_valid_for_queueing(self, url):
        parsed_url = urlparse(url)
        if (url in self.urls_ever_queued or parsed_url.netloc != self.base_netloc or any(url.lower().endswith(ext) for ext in ['.pdf','.jpg','.png','.css','.js','.zip','.ico']) or any(keyword in url.lower() for keyword in ['logout', 'signoff', 'logoff'])):
            return False
        return True

