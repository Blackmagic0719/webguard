import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def get_links(url, max_links=30):
    try:
        resp = requests.get(url, timeout=8, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        base = urlparse(url)

        links = set()
        for tag in soup.find_all(["a", "form", "script", "link"]):
            href = tag.get("href") or tag.get("src") or tag.get("action")
            if href:
                full = urljoin(url, href)
                parsed = urlparse(full)
                if parsed.netloc == base.netloc:
                    links.add(full)

        return list(links)[:max_links]
    except Exception as e:
        return []
