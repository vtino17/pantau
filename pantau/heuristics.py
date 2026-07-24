import re
from urllib.parse import urlparse

from .patterns import INDO_SCAM_KEYWORDS, SUSPICIOUS_TLDS, SUSPICIOUS_KEYWORDS_DOMAIN


def score_url(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.netloc.lower() or parsed.path.lower()
    path = parsed.path.lower()
    full = url.lower()

    # Strip www.
    domain = re.sub(r"^www\d*\.", "", domain)

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
        if brand in domain:
            exact = domain == f"{brand}.com" or domain == f"{brand}.co.id"
            if not exact:
                score += 35
                findings.append(f"Domain mencurigakan mirip '{brand}'")
                break

    # 3. Suspicious keywords in domain
    for kw in SUSPICIOUS_KEYWORDS_DOMAIN:
        if kw in domain:
            score += 20
            findings.append(f"Keyword mencurigakan di domain: '{kw}'")
            break

    # 4. Scam category keywords in path/domain
    for category, info in INDO_SCAM_KEYWORDS.items():
        for word in info["words"]:
            if word in domain or word in path or word in full:
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
