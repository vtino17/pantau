from urllib.parse import urlparse

from .heuristics import score_url, check_domain_reputation
from .expand import expand_url, is_shortener


def check(url: str, timeout: int = 10) -> dict:
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    result = {
        "original": url,
        "domain": domain,
        "expanded": None,
        "hops": [],
        "heuristics": score_url(url),
    }

    if is_shortener(domain):
        try:
            final, hops = expand_url(url, timeout)
            result["expanded"] = final
            result["hops"] = hops
            result["heuristics"] = score_url(final)
        except Exception as e:
            result["error"] = str(e)

    return result
