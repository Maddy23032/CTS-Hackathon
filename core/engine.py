import time
import hashlib
import re
from urllib.parse import urlparse, urljoin, parse_qs
import requests
from bs4 import BeautifulSoup
import concurrent.futures
import threading

# MODIFIED: Import is the same, but usage will change
from playwright.sync_api import sync_playwright, Page

from core.storage import FileStorage

class DiscoveryEngine:
    C_GREEN = '\033[92m'
    C_YELLOW = '\033[93m'
    C_RED = '\033[91m'
    C_BLUE = '\033[94m'
    C_RESET = '\033[0m'

    def __init__(self, base_url, max_depth=2, num_threads=10, login_url=None, login_data=None):
        self.base_url = base_url
        self.base_netloc = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.num_threads = num_threads
        self.login_url = login_url
        self.login_data = login_data
        
        self.storage = FileStorage(collection_name=self.base_netloc)
        self.session = self._create_requests_session()
        self.thread_local = threading.local()

        self.urls_ever_queued = {self.base_url}
        self.discovered_fingerprints = set()
        self.discovered_urls = []
        self.lock = threading.Lock()

        # REMOVED: No longer managing a single Playwright instance here
        # self.playwright: Playwright = None
        # self.browser: Browser = None

        self.FORBIDDEN_EXTENSIONS = ['.pdf','.jpg','.png','.css','.js','.zip','.ico','.gif','.svg','.webp']
        self.FORBIDDEN_KEYWORDS = ['logout', 'signoff', 'logoff']

    def _create_requests_session(self):
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'SecurityMapper/10.0 (Attack-Surface-Mapper)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'X-Scanner-Purpose': 'Hackathon-Discovery'
        })
        return session

    # MODIFIED: This function now creates and manages a full Playwright instance per thread
    def _get_playwright_page(self) -> Page:
        """
        Gets or creates a Playwright instance, browser, and page that is
        local and exclusive to the current thread.
        """
        if not hasattr(self.thread_local, 'page'):
            # This block runs only once for each thread
            self.thread_local.playwright = sync_playwright().start()
            self.thread_local.browser = self.thread_local.playwright.chromium.launch(headless=True)
            context = self.thread_local.browser.new_context(user_agent=self.session.headers['User-Agent'])
            self.thread_local.page = context.new_page()
        return self.thread_local.page

    def _perform_login(self):
        if not self.login_url or not self.login_data: return
        print(f"\n{self.C_BLUE}[AUTH] Attempting login to {self.login_url}...{self.C_RESET}")
        try:
            data_dict = dict(item.split('=') for item in self.login_data.split('&'))
            res = self.session.post(self.login_url, data=data_dict, allow_redirects=True)
            res.raise_for_status()
            print(f"{self.C_GREEN}[AUTH] Login successful. Session cookies will be used for all subsequent requests.{self.C_RESET}")
        except Exception as e:
            print(f"{self.C_RED}[AUTH] Login failed: {e}{self.C_RESET}")

    def _fetch_page_content(self, url):
        try:
            print(f"[FETCHING] Thread '{threading.current_thread().name}' fetching {url}...")
            response = self.session.get(url, timeout=15, allow_redirects=True)
            response.raise_for_status()
            if 'text/html' not in response.headers.get('Content-Type', ''): return None, response
            
            body_content = response.text.lower()
            if '<div id="root">' in body_content or '<div id="app">' in body_content or len(body_content) < 1000:
                print(f"{self.C_YELLOW}[HYBRID] JS-heavy page suspected at {url}. Switching to Playwright.{self.C_RESET}")
                page = self._get_playwright_page()
                page.goto(url, wait_until='domcontentloaded', timeout=20000)
                page.wait_for_load_state('networkidle', timeout=15000) 
                return page.content(), response
            
            return response.text, response
        except Exception as e:
            print(f"{self.C_RED}[ERROR] Request failed for {url}: {e}{self.C_RESET}")
            return None, None

    # ... The _process_url method has no changes ...
    def _process_url(self, url, depth):
        html_content, response = self._fetch_page_content(url)
        if not response: return []

        if not html_content:
            soup = BeautifulSoup("", 'html.parser')
        else:
            soup = BeautifulSoup(html_content, 'html.parser')
            
        fingerprint = self._get_page_fingerprint(soup, response)
        new_links_to_process = []

        with self.lock:
            if not fingerprint or fingerprint in self.discovered_fingerprints: return []
            self.discovered_fingerprints.add(fingerprint)
            self.discovered_urls.append(url)
            
            print(f"\n{self.C_GREEN}[DISCOVERY] New unique state found: {url}{self.C_RESET}\n")
            
            state_data = {
                "fingerprint": fingerprint,
                "url": url,
                "timestamp": time.time(),
                "attack_surface": {
                    "discoverable_url": url,
                    "input_vectors": self._extract_all_input_vectors(soup, response),
                },
                "technology_profile": self._fingerprint_technologies(response, soup),
                "authentication_context": {c.name: c.value for c in self.session.cookies},
                "request_template": self._generate_request_template(response)
            }
            self.storage.save_state(fingerprint, state_data)

        if html_content:
            for link_tag in soup.find_all('a', href=True):
                href = link_tag.get('href')
                if not href or href.strip().startswith(('javascript:', 'mailto:', '#', 'tel:')): continue
                absolute_url = urljoin(url, href.strip())
                parsed_url = urlparse(absolute_url)

                if (parsed_url.netloc != self.base_netloc or 
                    any(absolute_url.lower().endswith(ext) for ext in self.FORBIDDEN_EXTENSIONS) or 
                    any(kw in absolute_url.lower() for kw in self.FORBIDDEN_KEYWORDS)):
                    continue

                with self.lock:
                    if absolute_url not in self.urls_ever_queued:
                        self.urls_ever_queued.add(absolute_url)
                        if depth + 1 <= self.max_depth:
                            new_links_to_process.append((absolute_url, depth + 1))
        
        return new_links_to_process
    
    # MODIFIED: Simplified to remove the central Playwright management
    def run_discovery(self):
        start_time = time.time()
        self._perform_login()
        print(f"\n{self.C_BLUE}[INFO] Starting discovery with {self.num_threads} threads using Playwright for dynamic content.{self.C_RESET}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            active_futures = {executor.submit(self._process_url, self.base_url, 0)}
            while active_futures:
                for future in concurrent.futures.as_completed(active_futures.copy()):
                    active_futures.remove(future)
                    try:
                        new_links = future.result()
                        if new_links:
                            for link, depth in new_links:
                                active_futures.add(executor.submit(self._process_url, link, depth))
                    except Exception as exc:
                        print(f"{self.C_RED}[CRITICAL] A crawl task generated an exception: {exc}{self.C_RESET}")

        # Note: Thread-local browser processes are automatically cleaned up by the OS upon script exit.
        
        self.storage.flush_to_file()

        duration = time.time() - start_time
        print("\n" + "="*50 + f"\n          {self.C_GREEN}Discovery Complete{self.C_RESET}\n" + "="*50)
        print(f"Time Taken: {duration:.2f} seconds")
        print(f"Total Unique States Discovered: {len(self.discovered_fingerprints)}")

        if self.discovered_urls:
            print(f"\n{self.C_BLUE}[+] Summary of Discovered Unique URLs:{self.C_RESET}")
            for i, url in enumerate(self.discovered_urls, 1):
                print(f"  {i}. {url}")
        
        print(f"\nAll data has been saved to the output file.")
        print("="*50)
    
    # --- No changes to the methods below this line ---
    def _get_page_fingerprint(self, soup, response):
        headers = response.headers
        content_type = headers.get('Content-Type', '').split(';')[0]
        struct_parts = [f"content-type:{content_type}"]

        forms = soup.find_all('form')
        if forms:
            for form in sorted(forms, key=lambda f: str(f.get('action', ''))):
                struct_parts.append(f"form:{form.get('action', '')}:{form.get('method', 'get').lower()}")
        else:
            title = soup.find('title')
            if title: struct_parts.append(f"title:{title.get_text(strip=True)}")
        
        struct_fingerprint = hashlib.sha256('|'.join(struct_parts).encode()).hexdigest()
        
        text_to_hash = response.text if 'json' in content_type else soup.get_text(" ", strip=True)
        content_hash = hashlib.sha256(text_to_hash.encode()).hexdigest()

        return f"{struct_fingerprint[:16]}-{content_hash[:16]}"

    def _extract_all_input_vectors(self, soup, response):
        vectors = {
            "url_params": [], "forms": [], "cookies": [], "headers": [], "json_body": False
        }
        query = urlparse(response.url).query
        if query:
            vectors['url_params'] = [{"name": k, "value": v[0]} for k, v in parse_qs(query).items()]
        
        for form in soup.find_all('form'):
            details = {"action": urljoin(response.url, form.get('action')), "method": form.get('method', 'get').lower(), "fields": [{"name": i.get('name'), "type": i.get('type', 'text')} for i in form.find_all(['input', 'textarea', 'select']) if i.get('name')]}
            vectors['forms'].append(details)
            
        if 'Cookie' in response.request.headers:
            vectors['cookies'] = [{"name": c.split('=')[0].strip()} for c in response.request.headers['Cookie'].split(';')]

        interesting_headers = ['Authorization', 'X-API-Key', 'X-CSRF-Token', 'X-Scanner-Purpose']
        vectors['headers'] = [{"name": h, "value": v} for h, v in response.request.headers.items() if h in interesting_headers]

        if 'application/json' in response.headers.get('Content-Type', ''):
            vectors['json_body'] = True

        return vectors

    def _fingerprint_technologies(self, response, soup):
        tech = []
        headers = response.headers
        if 'Server' in headers:
            tech.append(f"Server: {headers['Server']}")
        if 'X-Powered-By' in headers:
            tech.append(f"X-Powered-By: {headers['X-Powered-By']}")
        if soup.find("meta", attrs={"name": "generator"}):
            tech.append(f"Generator: {soup.find('meta', attrs={'name': 'generator'}).get('content')}")
        return tech

    def _generate_request_template(self, response):
        req = response.request
        path_query = urlparse(req.url).path or '/'
        if urlparse(req.url).query:
            path_query += '?' + urlparse(req.url).query
        
        template = f"{req.method} {path_query} HTTP/1.1\n"
        template += f"Host: {urlparse(req.url).netloc}\n"
        template += "\n".join(f"{k}: {v}" for k, v in req.headers.items())
        
        if req.body:
            template += f"\n\n{req.body}"
        return template

# import time
# import hashlib
# import re
# from urllib.parse import urlparse, urljoin, parse_qs
# import requests
# from bs4 import BeautifulSoup
# import concurrent.futures
# import threading

# from selenium import webdriver
# from selenium.webdriver.chrome.service import Service as ChromeService
# from selenium.webdriver.chrome.options import Options
# from webdriver_manager.chrome import ChromeDriverManager

# from core.storage import FileStorage

# class DiscoveryEngine:
#     C_GREEN = '\033[92m'
#     C_YELLOW = '\033[93m'
#     C_RED = '\033[91m'
#     C_BLUE = '\033[94m'
#     C_RESET = '\033[0m'

#     def __init__(self, base_url, max_depth=2, num_threads=10, login_url=None, login_data=None):
#         self.base_url = base_url
#         self.base_netloc = urlparse(base_url).netloc
#         self.max_depth = max_depth
#         self.num_threads = num_threads
#         self.login_url = login_url
#         self.login_data = login_data
        
#         self.storage = FileStorage(collection_name=self.base_netloc)
        
#         self.session = self._create_requests_session()
#         self.thread_local = threading.local()

#         self.urls_ever_queued = {self.base_url}
#         self.discovered_fingerprints = set()
#         self.discovered_urls = []  # ADDED: A list to store unique URLs for the final summary
#         self.lock = threading.Lock()

#         self.FORBIDDEN_EXTENSIONS = ['.pdf','.jpg','.png','.css','.js','.zip','.ico','.gif','.svg','.webp']
#         self.FORBIDDEN_KEYWORDS = ['logout', 'signoff', 'logoff']

#     def _create_requests_session(self):
#         session = requests.Session()
#         session.headers.update({
#             'User-Agent': 'SecurityMapper/10.0 (Attack-Surface-Mapper)',
#             'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
#             'X-Scanner-Purpose': 'Hackathon-Discovery'
#         })
#         return session

#     def _get_selenium_driver(self):
#         if not hasattr(self.thread_local, 'driver'):
#             chrome_options = Options()
#             chrome_options.add_argument("--headless")
#             chrome_options.add_argument("--no-sandbox")
#             chrome_options.add_argument("--disable-dev-shm-usage")
#             chrome_options.add_argument("--disable-gpu")
#             chrome_options.add_argument("user-agent=" + self.session.headers['User-Agent'])
#             chrome_options.add_experimental_option('excludeSwitches', ['enable-logging', 'enable-automation'])
#             chrome_options.add_argument('--log-level=3')
#             service = ChromeService(ChromeDriverManager().install())
#             self.thread_local.driver = webdriver.Chrome(service=service, options=chrome_options)
#         return self.thread_local.driver

#     def _perform_login(self):
#         if not self.login_url or not self.login_data: return
#         print(f"\n{self.C_BLUE}[AUTH] Attempting login to {self.login_url}...{self.C_RESET}")
#         try:
#             data_dict = dict(item.split('=') for item in self.login_data.split('&'))
#             res = self.session.post(self.login_url, data=data_dict, allow_redirects=True)
#             res.raise_for_status()
#             print(f"{self.C_GREEN}[AUTH] Login successful. Session cookies will be used for all subsequent requests.{self.C_RESET}")
#         except Exception as e:
#             print(f"{self.C_RED}[AUTH] Login failed: {e}{self.C_RESET}")

#     def _fetch_page_content(self, url):
#         try:
#             print(f"[FETCHING] Thread '{threading.current_thread().name}' fetching {url}...")
#             response = self.session.get(url, timeout=15, allow_redirects=True)
#             response.raise_for_status()
#             if 'text/html' not in response.headers.get('Content-Type', ''): return None, response
            
#             body_content = response.text.lower()
#             if '<div id="root">' in body_content or '<div id="app">' in body_content or len(body_content) < 1000:
#                 print(f"{self.C_YELLOW}[HYBRID] JS-heavy page suspected at {url}. Switching to Selenium.{self.C_RESET}")
#                 driver = self._get_selenium_driver()
#                 driver.get(url)
#                 time.sleep(3)
#                 return driver.page_source, response
            
#             return response.text, response
#         except requests.RequestException as e:
#             print(f"{self.C_RED}[ERROR] Request failed for {url}: {e}{self.C_RESET}")
#             return None, None

#     def _process_url(self, url, depth):
#         html_content, response = self._fetch_page_content(url)
#         if not response: return []

#         if not html_content:
#             soup = BeautifulSoup("", 'html.parser')
#         else:
#             soup = BeautifulSoup(html_content, 'html.parser')
            
#         fingerprint = self._get_page_fingerprint(soup, response)
#         new_links_to_process = []

#         with self.lock:
#             if not fingerprint or fingerprint in self.discovered_fingerprints: return []
#             self.discovered_fingerprints.add(fingerprint)
#             self.discovered_urls.append(url) # ADDED: Save the URL to our new list
            
#             print(f"\n{self.C_GREEN}[DISCOVERY] New unique state found: {url}{self.C_RESET}\n")
            
#             state_data = {
#                 "fingerprint": fingerprint,
#                 "url": url,
#                 "timestamp": time.time(),
#                 "attack_surface": {
#                     "discoverable_url": url,
#                     "input_vectors": self._extract_all_input_vectors(soup, response),
#                 },
#                 "technology_profile": self._fingerprint_technologies(response, soup),
#                 "authentication_context": {c.name: c.value for c in self.session.cookies},
#                 "request_template": self._generate_request_template(response)
#             }
#             self.storage.save_state(fingerprint, state_data)

#         if html_content:
#             for link_tag in soup.find_all('a', href=True):
#                 href = link_tag.get('href')
#                 if not href or href.strip().startswith(('javascript:', 'mailto:', '#', 'tel:')): continue
#                 absolute_url = urljoin(url, href.strip())
#                 parsed_url = urlparse(absolute_url)

#                 if (parsed_url.netloc != self.base_netloc or 
#                     any(absolute_url.lower().endswith(ext) for ext in self.FORBIDDEN_EXTENSIONS) or 
#                     any(kw in absolute_url.lower() for kw in self.FORBIDDEN_KEYWORDS)):
#                     continue

#                 with self.lock:
#                     if absolute_url not in self.urls_ever_queued:
#                         self.urls_ever_queued.add(absolute_url)
#                         if depth + 1 <= self.max_depth:
#                             new_links_to_process.append((absolute_url, depth + 1))
        
#         return new_links_to_process
    
#     def run_discovery(self):
#         start_time = time.time()
#         self._perform_login()
#         print(f"\n{self.C_BLUE}[INFO] Starting discovery with {self.num_threads} threads. Output will be saved to a text file.{self.C_RESET}")
        
#         with concurrent.futures.ThreadPoolExecutor(max_workers=self.num_threads) as executor:
#             active_futures = {executor.submit(self._process_url, self.base_url, 0)}
#             while active_futures:
#                 for future in concurrent.futures.as_completed(active_futures.copy()):
#                     active_futures.remove(future)
#                     try:
#                         new_links = future.result()
#                         if new_links:
#                             for link, depth in new_links:
#                                 active_futures.add(executor.submit(self._process_url, link, depth))
#                     except Exception as exc:
#                         print(f"{self.C_RED}[CRITICAL] A crawl task generated an exception: {exc}{self.C_RESET}")
            
#             if hasattr(self.thread_local, 'driver'):
#                 self.thread_local.driver.quit()

#         self.storage.flush_to_file()

#         duration = time.time() - start_time
#         print("\n" + "="*50 + f"\n          {self.C_GREEN}Discovery Complete{self.C_RESET}\n" + "="*50)
#         print(f"Time Taken: {duration:.2f} seconds")
#         print(f"Total Unique States Discovered: {len(self.discovered_fingerprints)}")

#         # ADDED: This block prints the final summary of discovered URLs
#         if self.discovered_urls:
#             print(f"\n{self.C_BLUE}[+] Summary of Discovered Unique URLs:{self.C_RESET}")
#             for i, url in enumerate(self.discovered_urls, 1):
#                 print(f"  {i}. {url}")
        
#         print(f"\nAll data has been saved to the output file.")
#         print("="*50)

#     def _get_page_fingerprint(self, soup, response):
#         headers = response.headers
#         content_type = headers.get('Content-Type', '').split(';')[0]
#         struct_parts = [f"content-type:{content_type}"]

#         forms = soup.find_all('form')
#         if forms:
#             for form in sorted(forms, key=lambda f: str(f.get('action', ''))):
#                 struct_parts.append(f"form:{form.get('action', '')}:{form.get('method', 'get').lower()}")
#         else:
#             title = soup.find('title')
#             if title: struct_parts.append(f"title:{title.get_text(strip=True)}")
        
#         struct_fingerprint = hashlib.sha256('|'.join(struct_parts).encode()).hexdigest()
        
#         text_to_hash = response.text if 'json' in content_type else soup.get_text(" ", strip=True)
#         content_hash = hashlib.sha256(text_to_hash.encode()).hexdigest()

#         return f"{struct_fingerprint[:16]}-{content_hash[:16]}"

#     def _extract_all_input_vectors(self, soup, response):
#         vectors = {
#             "url_params": [], "forms": [], "cookies": [], "headers": [], "json_body": False
#         }
#         query = urlparse(response.url).query
#         if query:
#             vectors['url_params'] = [{"name": k, "value": v[0]} for k, v in parse_qs(query).items()]
        
#         for form in soup.find_all('form'):
#             details = {"action": urljoin(response.url, form.get('action')), "method": form.get('method', 'get').lower(), "fields": [{"name": i.get('name'), "type": i.get('type', 'text')} for i in form.find_all(['input', 'textarea', 'select']) if i.get('name')]}
#             vectors['forms'].append(details)
            
#         if 'Cookie' in response.request.headers:
#             vectors['cookies'] = [{"name": c.split('=')[0].strip()} for c in response.request.headers['Cookie'].split(';')]

#         interesting_headers = ['Authorization', 'X-API-Key', 'X-CSRF-Token', 'X-Scanner-Purpose']
#         vectors['headers'] = [{"name": h, "value": v} for h, v in response.request.headers.items() if h in interesting_headers]

#         if 'application/json' in response.headers.get('Content-Type', ''):
#             vectors['json_body'] = True

#         return vectors

#     def _fingerprint_technologies(self, response, soup):
#         tech = []
#         headers = response.headers
#         if 'Server' in headers:
#             tech.append(f"Server: {headers['Server']}")
#         if 'X-Powered-By' in headers:
#             tech.append(f"X-Powered-By: {headers['X-Powered-By']}")
#         if soup.find("meta", attrs={"name": "generator"}):
#             tech.append(f"Generator: {soup.find('meta', attrs={'name': 'generator'}).get('content')}")
#         return tech

#     def _generate_request_template(self, response):
#         req = response.request
#         path_query = urlparse(req.url).path or '/'
#         if urlparse(req.url).query:
#             path_query += '?' + urlparse(req.url).query
        
#         template = f"{req.method} {path_query} HTTP/1.1\n"
#         template += f"Host: {urlparse(req.url).netloc}\n"
#         template += "\n".join(f"{k}: {v}" for k, v in req.headers.items())
        
#         if req.body:
#             template += f"\n\n{req.body}"
#         return template