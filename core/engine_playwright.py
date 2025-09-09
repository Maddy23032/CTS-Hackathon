# core/engine_playwright.py
import asyncio
import hashlib
import re
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
from datetime import datetime

from playwright.async_api import async_playwright

_SKIP_EXT = ('.pdf','.jpg','.jpeg','.png','.gif','.webp','.css','.js','.zip','.ico','.svg','.woff','.woff2','.ttf','.eot','.mp4','.mp3','.avi','.mov')

class PlaywrightDiscoveryEngine:
    """
    JS-aware discovery: renders pages, captures DOM, finds links/forms, and samples network (XHR/fetch).
    Produces the same contract as DiscoveryEngine: discovered_states + tech_profile + sample_logs.
    """
    def __init__(self, base_url, max_depth=2, concurrency=5, login_url=None, login_data=None):
        self.base_url = base_url
        self.base_netloc = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.concurrency = concurrency
        self.login_url = login_url
        self.login_data = login_data

        # Outputs
        self.discovered_states = {}   # fingerprint -> state {url,parent,depth,input_vectors,request_template,content_hash}
        self.tech_profile = set()
        self.sample_logs = []         # sampled http logs: method,url,status,timestamp,kind

        # Internal
        self._seen_urls = set([self.base_url])

    # ---------- public API ----------
    def run_discovery(self):
        return asyncio.run(self._run())

    # ---------- helpers ----------
    def _is_same_site(self, url):
        return urlparse(url).netloc == self.base_netloc

    def _is_valid_for_queueing(self, url):
        url_l = url.lower()
        if url in self._seen_urls:
            return False
        if not self._is_same_site(url):
            return False
        if url_l.endswith(_SKIP_EXT):
            return False
        if any(k in url_l for k in ['logout','signoff','logoff']):
            return False
        return True

    def _get_page_fingerprint(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        structural_elements = []
        forms = soup.find_all('form')
        if forms:
            for form in sorted(forms, key=lambda f: f.get('action', '') or ''):
                action = form.get('action', '') or ''
                method = (form.get('method') or 'get').lower()
                structural_elements.append(f"form:{action}:{method}")
        else:
            title = soup.find('title')
            if title:
                structural_elements.append(f"title:{title.get_text()}")
        struct_fingerprint = hashlib.sha256('|'.join(structural_elements).encode('utf-8','ignore')).hexdigest()
        text_content = re.sub(r'\s+', ' ', soup.get_text(" ", strip=True))
        content_hash = hashlib.sha256(text_content.encode('utf-8','ignore')).hexdigest()
        return f"{struct_fingerprint}-{content_hash}", content_hash, soup

    def _extract_vectors(self, soup, final_url, request_headers, cookies):
        vectors = {"url_params": [], "forms": [], "cookies": [], "headers": []}
        # URL params
        query = urlparse(final_url).query
        if query:
            vectors['url_params'] = [{"name": k} for k in parse_qs(query).keys()]
        # Forms
        for form in soup.find_all('form'):
            action = urljoin(final_url, form.get('action') or '')
            method = (form.get('method') or 'get').lower()
            fields = []
            for i in form.find_all(['input','textarea','select','button']):
                nm = i.get('name')
                tp = i.get('type','text')
                if nm:
                    fields.append({"name": nm, "type": tp})
            vectors['forms'].append({"action": action, "method": method, "fields": fields})
        # Cookies
        if cookies:
            vectors['cookies'] = [{"name": c.get('name')} for c in cookies if c.get('name')]
        # Interesting headers
        interesting = {'authorization','x-forwarded-for','x-client-ip','x-real-ip','referer','x-api-key','api-key','x-csrf-token'}
        for k in (request_headers or {}).keys():
            if k.lower() in interesting:
                vectors['headers'].append({"name": k})
        return vectors

    def _fingerprint_tech(self, headers):
        h = {k.lower(): v for k,v in (headers or {}).items()}
        if 'server' in h: self.tech_profile.add(f"server:{h['server']}")
        if 'x-powered-by' in h: self.tech_profile.add(f"powered-by:{h['x-powered-by']}")
        if 'x-aspnet-version' in h: self.tech_profile.add(f"tech:ASP.NET {h['x-aspnet-version']}")

    async def _run(self):
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True)
            # If you need custom UA/headers/cookies, set on context here.

            # Optional: scripted login
            if self.login_url and self.login_data:
                page = await context.new_page()
                try:
                    await page.goto(self.login_url, wait_until="domcontentloaded", timeout=15000)
                    # naive login post if login_data is URL-encoded fields: "user=a&pass=b"
                    kv = dict(item.split('=',1) for item in self.login_data.split('&') if '=' in item)
                    # attempt fill by name
                    for name, val in kv.items():
                        sel = f'input[name="{name}"]'
                        if await page.locator(sel).count() > 0:
                            await page.fill(sel, val)
                    # click first submit button
                    if await page.locator('form >> input[type="submit"], form >> button[type="submit"]').count() > 0:
                        await page.locator('form >> input[type="submit"], form >> button[type="submit"]').first.click()
                    await page.wait_for_load_state("domcontentloaded", timeout=15000)
                finally:
                    await page.close()

            # BFS with concurrency
            q = asyncio.Queue()
            await q.put((self.base_url, 0, None))   # (url, depth, parent)
            sem = asyncio.Semaphore(self.concurrency)
            tasks = []
            for _ in range(self.concurrency):
                tasks.append(asyncio.create_task(self._worker(context, q, sem)))
            await q.join()
            for t in tasks:
                t.cancel()
            await browser.close()
        return self._format_text_report()

    async def _worker(self, context, q, sem):
        while True:
            try:
                url, depth, parent = await q.get()
            except Exception:
                return
            try:
                if depth > self.max_depth:
                    continue
                async with sem:
                    page = await context.new_page()

                    # capture network (XHR/fetch/doc) for sampling
                    page_req_log = []
                    page.on("request", lambda req: page_req_log.append({
                        "kind": req.resource_type,
                        "method": req.method,
                        "url": req.url,
                        "ts": datetime.utcnow().isoformat()
                    }))

                    response = await page.goto(url, wait_until="domcontentloaded", timeout=20000)
                    # collect headers for tech profile
                    try:
                        self._fingerprint_tech(await response.all_headers()) if response else None
                    except Exception:
                        pass

                    html = await page.content()
                    fp, content_hash, soup = self._get_page_fingerprint(html)

                    if fp not in self.discovered_states:
                        # vectors
                        req_headers = {}  # could read from context, varies by site
                        cookies = await context.cookies()
                        vectors = self._extract_vectors(soup, response.url if response else url, req_headers, cookies)

                        # request template (best-effort)
                        parsed = urlparse(response.url if response else url)
                        full_path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
                        request_template = f"GET {full_path} HTTP/1.1\nHost: {parsed.netloc}\nUser-Agent: PlaywrightCrawler"

                        self.discovered_states[fp] = {
                            "url": response.url if response else url,
                            "parent": parent,
                            "depth": depth,
                            "input_vectors": vectors,
                            "request_template": request_template,
                            "content_hash": content_hash
                        }

                        # extract links from rendered DOM
                        links = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                        for href in set(links or []):
                            absu = href
                            if self._is_valid_for_queueing(absu):
                                self._seen_urls.add(absu)
                                await q.put((absu, depth+1, response.url if response else url))

                        # sample network items (fetch/xhr/document)
                        for r in page_req_log:
                            if r["kind"] in ("xhr","fetch","document"):
                                self.sample_logs.append({
                                    "method": r["method"],
                                    "url": r["url"],
                                    "status": None,  # we could also hook on 'response' to fill this
                                    "kind": r["kind"],
                                    "timestamp": r["ts"]
                                })
                    await page.close()
            except Exception:
                # ignore per-page failures
                pass
            finally:
                q.task_done()

    def _format_text_report(self):
        # For compatibility with your existing CLI return style
        return f"JS Crawler finished. Unique states: {len(self.discovered_states)}"
