import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque, defaultdict
import time
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

class Crawler:
    def _is_in_scope(self, url):
        """Checks if a URL is within the target's domain."""
        return urlparse(url).netloc == self.base_netloc

    def _is_irrelevant(self, url):
        irrelevant_extensions = ['.pdf', '.zip', '.jpg', '.png', '.gif', '.css', '.js', '.ico', '.svg']
        irrelevant_keywords = ['logout', 'twitter.com', 'facebook.com', 'linkedin.com', 'instagram.com', 'mailto:', 'javascript:']
        url_lower = url.lower()
        if any(ext in url_lower for ext in irrelevant_extensions):
            return True
        if any(keyword in url_lower for keyword in irrelevant_keywords):
            return True
        return False
    """
    Scope-aware web crawler for VulnScan.
    Discovers all in-scope links, forms, and input vectors.
    """
    def __init__(self, base_url, cookie=None, delay=0, verbose=False, max_depth=3, max_pages=100, use_browser=False, min_delay=0, max_delay=10):
        self.base_url = base_url
        self.base_netloc = urlparse(base_url).netloc
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'VulnScan/1.0 (Automated Security Scanner)'})
        if cookie:
            self.session.headers.update({'Cookie': cookie})
        self.delay = delay
        self.min_delay = min_delay if min_delay is not None else 0
        self.max_delay = max_delay if max_delay is not None else 10
        self.verbose = verbose
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.use_browser = use_browser
        self.visited_urls = set()
        self.visited_content_hashes = set()  # Content-based fingerprinting
        self.error_page_hashes = set()  # Soft 404 detection
        self.duplicate_skipped = 0  # Track efficiency gains
        
        # Burp Suite-style advanced features
        self.page_graph = defaultdict(set)  # Directed graph of page transitions
        self.csrf_tokens = {}  # Track CSRF tokens per form/page
        self.dynamic_params = {}  # Track dynamic form parameters
        self.session_state = {}  # Track session state
        self.url_to_content_map = {}  # Map normalized URLs to content hashes
        
        self.attack_surface = {
            'urls': set(),
            'forms': []
        }
        self._consecutive_429 = 0

    def log(self, msg):
        if self.verbose:
            print(f"[Crawler] {msg}")

    def _is_error_page(self, html_content):
        """Detect custom error pages by looking for common error indicators."""
        error_indicators = [
            'page not found', '404 not found', 'file not found',
            'the page you requested was not found', 'this page does not exist',
            'the requested page could not be found', 'broken link',
            'invalid page', 'page cannot be displayed'
        ]
        content_lower = html_content.lower()
        # Require multiple indicators or very specific phrases
        indicator_count = sum(1 for indicator in error_indicators if indicator in content_lower)
        return indicator_count >= 2 or any(specific in content_lower for specific in ['404 not found', 'page not found'])

    def _normalize_url(self, url):
        """Normalize URL by removing ephemeral tokens (session IDs, timestamps, etc.)"""
        parsed = urlparse(url)
        if parsed.query:
            # Remove common ephemeral parameters
            ephemeral_params = ['sessionid', 'jsessionid', 'phpsessid', 'aspxsessionid', 'timestamp', '_t', 'rnd', 'cache']
            query_params = parse_qs(parsed.query)
            filtered_params = {k: v for k, v in query_params.items() 
                             if not any(ephemeral in k.lower() for ephemeral in ephemeral_params)}
            if filtered_params:
                from urllib.parse import urlencode
                new_query = urlencode(filtered_params, doseq=True)
                return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            else:
                return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def _extract_csrf_tokens(self, soup, url):
        """Extract CSRF tokens and dynamic parameters from page (Burp Suite-style)"""
        tokens = {}
        
        # Look for common CSRF token patterns
        csrf_patterns = [
            'csrf_token', 'csrftoken', '_token', 'authenticity_token', 
            '__RequestVerificationToken', '_RequestVerificationToken'
        ]
        
        # Extract from hidden input fields
        for pattern in csrf_patterns:
            hidden_input = soup.find('input', {'name': pattern, 'type': 'hidden'})
            if hidden_input and hidden_input.get('value'):
                tokens[pattern] = hidden_input.get('value')
                self.log(f"[Session] CSRF token found: {pattern} = {hidden_input.get('value')[:20]}...")
        
        # Extract from meta tags
        for pattern in csrf_patterns:
            meta_tag = soup.find('meta', {'name': pattern})
            if meta_tag and meta_tag.get('content'):
                tokens[pattern] = meta_tag.get('content')
                self.log(f"[Session] CSRF token (meta) found: {pattern} = {meta_tag.get('content')[:20]}...")
        
        # Store tokens for this URL
        if tokens:
            self.csrf_tokens[url] = tokens
        
        return tokens

    def crawl(self):
        # queue holds (url, depth)
        queue = deque([(self.base_url, 0)])
        max_workers = 8
        futures = set()
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            while queue and len(self.visited_urls) < self.max_pages:
                batch = []
                # Prepare a batch of URLs to fetch in parallel
                while queue and len(batch) < max_workers and len(self.visited_urls) + len(batch) < self.max_pages:
                    url, depth = queue.popleft()
                    if url in self.visited_urls or depth > self.max_depth or not self._is_in_scope(url) or self._is_irrelevant(url):
                        continue
                    batch.append((url, depth))
                # Submit all in batch
                for url, depth in batch:
                    futures.add(executor.submit(self._fetch_and_parse, url, depth))
                # As each finishes, process results and add new URLs to queue
                for future in as_completed(futures):
                    res = future.result()
                    if not res:
                        continue
                    url, depth, links, forms, url_params = res
                    self.visited_urls.add(url)
                    for link in links:
                        if link not in self.visited_urls and self._is_in_scope(link) and not self._is_irrelevant(link):
                            queue.append((link, depth + 1))
                    for form in forms:
                        self.attack_surface['forms'].append(form)
                    for url_param in url_params:
                        self.attack_surface['urls'].add(url_param)
                    futures.remove(future)
                    if len(self.visited_urls) >= self.max_pages:
                        break
        
        # Log efficiency gains from content fingerprinting
        self.log(f"[Fingerprint Summary] Unique pages: {len(self.visited_content_hashes)}, Duplicates skipped: {self.duplicate_skipped}")
        if self.error_page_hashes:
            self.log(f"[Fingerprint Summary] Error page templates detected: {len(self.error_page_hashes)}")
        
        return self.attack_surface

    def _fetch_and_parse(self, url, depth):
        self.log(f"Visiting: {url} (depth {depth}) [{len(self.visited_urls)}/{self.max_pages}]")
        try:
            resp = self.session.get(url, timeout=(5, 10))
            # Smart rate limiting: check for 429 and adapt delay
            if resp.status_code == 429:
                self._consecutive_429 += 1
                self.delay = min(self.delay * 2 if self.delay else 1, self.max_delay)
                self.log(f"[RateLimit] 429 Too Many Requests detected. Increasing delay to {self.delay:.2f}s (consecutive 429s: {self._consecutive_429})")
                if self._consecutive_429 >= 3:
                    self.log("[RateLimit] Multiple 429s detected. Consider pausing or reducing scan speed.")
            else:
                if self._consecutive_429 > 0:
                    self._consecutive_429 = 0
                # Gradually decrease delay if no 429s for a while
                if self.delay > self.min_delay:
                    self.delay = max(self.delay * 0.9, self.min_delay)
            time.sleep(self.delay)
            
            # Burp Suite-style content fingerprinting with normalized URLs
            normalized_url = self._normalize_url(url)
            content_hash = hashlib.sha256(resp.content).hexdigest()
            
            # Check for duplicate content using normalized URL mapping
            if normalized_url in self.url_to_content_map:
                existing_hash = self.url_to_content_map[normalized_url]
                if existing_hash == content_hash:
                    self.duplicate_skipped += 1
                    self.log(f"[Fingerprint] Duplicate content detected for {url} (normalized: {normalized_url}). Skipping scan. (Total duplicates skipped: {self.duplicate_skipped})")
                    return None
            
            # Check for soft 404s (custom error pages)
            if resp.status_code in [404, 500, 403] or self._is_error_page(resp.text):
                self.error_page_hashes.add(content_hash)
                self.log(f"[Fingerprint] Error page detected: {url} (status: {resp.status_code})")
                return None
            elif content_hash in self.error_page_hashes:
                self.log(f"[Fingerprint] Soft 404 detected: {url} (matches known error page)")
                return None
            
            # Map normalized URL to content hash
            self.url_to_content_map[normalized_url] = content_hash
            self.visited_content_hashes.add(content_hash)
            
        except requests.exceptions.Timeout:
            self.log(f"[!] Request to {url} timed out. Skipping.")
            return None
        except Exception as e:
            self.log(f"Request failed: {e}")
            return None
        if 'text/html' not in resp.headers.get('Content-Type', ''):
            return None
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # Extract CSRF tokens and dynamic parameters (Burp Suite-style)
        self._extract_csrf_tokens(soup, url)
        
        # Discover links
        links = []
        for a in soup.find_all('a', href=True):
            href = a['href']
            if not href or not isinstance(href, str):
                continue
            try:
                abs_url = urljoin(url, href)
                parsed = urlparse(abs_url)
            except Exception as e:
                self.log(f"Skipping invalid href '{href}': {e}")
                continue
            if parsed.netloc == self.base_netloc and abs_url not in self.visited_urls and self._is_in_scope(abs_url) and not self._is_irrelevant(abs_url):
                links.append(abs_url)
                # Build directed graph of page transitions
                self.page_graph[url].add(abs_url)
        
        # Discover forms with enhanced session handling
        forms = []
        for form in soup.find_all('form'):
            form_details = self.parse_form_enhanced(form, url, soup)
            forms.append(form_details)
        
        # Discover URL parameters
        url_params = []
        parsed_url = urlparse(url)
        if parsed_url.query:
            params = tuple(parse_qs(parsed_url.query).keys())
            url_params.append((url, params))
        return (url, depth, links, forms, url_params)

    def parse_form_enhanced(self, form, page_url, soup):
        """Enhanced form parsing with CSRF token extraction (Burp Suite-style)"""
        action = form.get('action')
        method = form.get('method', 'get').lower()
        form_url = urljoin(page_url, action) if action else page_url
        
        inputs = []
        csrf_tokens = {}
        
        for inp in form.find_all(['input', 'textarea', 'select']):
            name = inp.get('name')
            value = inp.get('value', '')
            input_type = inp.get('type', 'text')
            
            if name:
                inputs.append(name)
                
                # Check if this is a CSRF token field
                if input_type == 'hidden' and any(token_name in name.lower() for token_name in ['csrf', 'token', 'authenticity']):
                    csrf_tokens[name] = value
                    self.log(f"[Session] CSRF token in form: {name} = {value[:20]}...")
        
        return {
            'url': form_url,
            'method': method,
            'inputs': inputs,
            'csrf_tokens': csrf_tokens  # Include CSRF tokens for scanning
        }
