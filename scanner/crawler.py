from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time

def crawl_website(start_url, max_depth, session):
    visited_urls = set()
    queue = [(start_url, 0)]
    base_netloc = urlparse(start_url).netloc

    while queue:
        url, depth = queue.pop(0)
        if url in visited_urls or depth > max_depth:
            continue
        try:
            response = session.get(url)
            response.raise_for_status()
            visited_urls.add(url)
            soup = BeautifulSoup(response.text, "html.parser")

            for link in soup.find_all("a", href=True):
                absolute_url = urljoin(url, link["href"])
                if urlparse(absolute_url).netloc == base_netloc and absolute_url not in visited_urls:
                    queue.append((absolute_url, depth + 1))

            time.sleep(0.5)  # Polite crawling delay
        except:
            visited_urls.add(url)

    return visited_urls
