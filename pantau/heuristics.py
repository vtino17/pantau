import re
from urllib.parse import urlparse

from .patterns import INDO_SCAM_KEYWORDS, SUSPICIOUS_TLDS, SUSPICIOUS_KEYWORDS_DOMAIN

# Below this length a keyword collides with ordinary words too often to be
# matched as a prefix or suffix ("bri" inside "cambridge", "tri" inside
# "district", "pos" inside "repository"), so short keywords must line up with a
# whole label.
_MIN_AFFIX_LEN = 4

_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def _tokens(*parts: str) -> list:
    """Split URL components into comparable labels.

    Domains and paths are delimited by dots, slashes and hyphens, and scam
    domains lean on exactly those separators ('bri-mobile', 'cek-bansos'), so
    splitting on non-alphanumerics keeps detection while giving each keyword a
    boundary to match against.
    """
    out = []
    for part in parts:
        out.extend(t for t in _TOKEN_SPLIT.split(part or "") if t)
    return out


def _is_official_domain(word: str, domain: str) -> bool:
    """True when the domain *is* the brand rather than imitating it.

    Without this the keyword lists flag their own subjects: tokopedia.com was
    reported as "E-commerce palsu" for containing 'tokopedia'.
    """
    return domain in (f"{word}.com", f"{word}.co.id", f"{word}.id")


def _keyword_hit(word: str, tokens: list) -> bool:
    """True when `word` lines up with a token boundary rather than landing
    anywhere inside one."""
    for token in tokens:
        if token == word:
            return True
        if len(word) >= _MIN_AFFIX_LEN and (token.startswith(word) or token.endswith(word)):
            return True
    return False


def score_url(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.netloc.lower() or parsed.path.lower()
    path = parsed.path.lower()
    full = url.lower()

    # Strip www.
    domain = re.sub(r"^www\d*\.", "", domain)

    domain_tokens = _tokens(domain)
    all_tokens = _tokens(domain, path)

    findings = []
    score = 0

    # 1. Suspicious TLD
    for level, tlds in SUSPICIOUS_TLDS.items():
        for tld in tlds:
            if domain.endswith("." + tld):
                risk = 30 if level == "high" else 15
                score += risk
                findings.append(f"TLD mencurigakan (.{tld})")
                break

    # 2. Check for typo-squatting (popular domains with extra chars)
    popular = ["tokopedia", "shopee", "lazada", "bukalapak", "google", "facebook", "instagram", "gojek", "grab", "bri", "bca", "mandiri"]
    for brand in popular:
        if _keyword_hit(brand, domain_tokens):
            exact = domain == f"{brand}.com" or domain == f"{brand}.co.id"
            if not exact:
                score += 35
                findings.append(f"Domain mencurigakan mirip '{brand}'")
                break

    # 3. Suspicious keywords in domain
    for kw in SUSPICIOUS_KEYWORDS_DOMAIN:
        if _keyword_hit(kw, domain_tokens):
            score += 20
            findings.append(f"Keyword mencurigakan di domain: '{kw}'")
            break

    # 4. Scam category keywords in path/domain
    for category, info in INDO_SCAM_KEYWORDS.items():
        for word in info["words"]:
            if _is_official_domain(word, domain):
                continue
            if _keyword_hit(word, all_tokens):
                risk_score = 30 if info["risk"] == "high" else 15
                score += risk_score
                findings.append(f"{info['label']}: mengandung '{word}'")
                break

    # 5. IP address instead of domain
    if re.match(r"^\d+\.\d+\.\d+\.\d+", domain):
        score += 40
        findings.append("Domain berupa alamat IP (bukan nama domain)")

    # 6. Too many subdomains
    parts = domain.split(".")
    if len(parts) > 4:
        score += 15
        findings.append("Terlalu banyak subdomain")

    # 7. Long domain
    if len(domain) > 40:
        score += 10
        findings.append("Domain sangat panjang")

    # 8. Contains @
    if "@" in url:
        score += 30
        findings.append("Mengandung karakter '@' (phishing pattern)")

    # 9. Double https/http
    if re.search(r"https?://.*https?://", url):
        score += 40
        findings.append("URL bersarang (redirect berantai mencurigakan)")

    # 10. Shortener
    from .expand import is_shortener
    if is_shortener(domain):
        score += 15
        findings.append("Menggunakan URL shortener")

    risk_level = "aman"
    if score >= 70:
        risk_level = "bahaya"
    elif score >= 40:
        risk_level = "mencurigakan"
    elif score >= 15:
        risk_level = "ringan"

    return {
        "score": min(score, 100),
        "level": risk_level,
        "findings": findings,
        "domain": domain,
    }


def check_domain_reputation(domain: str) -> dict:
    parsed = urlparse(domain if "://" in domain else f"https://{domain}")
    clean = parsed.netloc.lower() or parsed.path.lower()
    clean = re.sub(r"^www\d*\.", "", clean)
    return score_url(f"https://{clean}/")
