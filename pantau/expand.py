import urllib.request
import urllib.error

SHORTENER_DOMAINS = {
    "s.id", "bit.ly", "bitly.com", "tinyurl.com", "shorturl.at", "t.ly",
    "rb.gy", "cutt.ly", "ow.ly", "is.gd", "buff.ly", "tiny.cc", "tr.im",
    "v.gd", "short.link", "click.link", "short.cm", "short.gy",
    "s.id", "s.id.id", "x.co", "goo.gl", "shortener", "shorten",
}

def is_shortener(domain: str) -> bool:
    domain = domain.lower().strip()
    for s in SHORTENER_DOMAINS:
        if s in domain or domain.endswith("." + s):
            return True
    return False

def expand_url(url: str, timeout: int = 10) -> tuple[str, list[str]]:
    hops = [url]
    visited = set()
    for _ in range(10):
        if url in visited:
            break
        visited.add(url)
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Pantau/0.1",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
                method="HEAD",
            )
            resp = urllib.request.urlopen(req, timeout=timeout)
            final = resp.geturl()
            if final != url:
                hops.append(final)
                url = final
            else:
                break
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):
                loc = e.headers.get("Location")
                if loc:
                    hops.append(loc)
                    url = loc
                    continue
            break
        except Exception:
            break
    return hops[-1], hops
