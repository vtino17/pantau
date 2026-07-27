"""Scoring tests, weighted towards false positives.

A link checker that calls ordinary sites dangerous gets ignored, so the
legitimate-URL cases matter at least as much as the phishing ones.
"""

import pytest

from pantau.heuristics import check_domain_reputation, score_url


LEGITIMATE = [
    "https://www.cambridge.org/",
    "https://en.wikipedia.org/wiki/Industrial_district",
    "https://github.com/user/repository",
    "https://wordpress.com/post/123",
    "https://www.bluetooth.com/",
    "https://www.python.org/downloads/",
    "https://docs.djangoproject.com/en/stable/topics/http/urls/",
]

OFFICIAL_BRAND_DOMAINS = [
    "https://www.tokopedia.com/",
    "https://www.shopee.co.id/",
    "https://www.bukalapak.com/",
    "https://www.gojek.com/",
]

PHISHING = [
    "http://bri-mobile.tk/login",
    "http://cek-bansos.xyz/daftar",
    "http://shopee-promo.ga/hadiah",
    "http://tokopedia-flashsale.ml/",
    "http://shopee.com.verify-akun.tk/",
]


class TestLegitimateUrls:

    @pytest.mark.parametrize("url", LEGITIMATE)
    def test_ordinary_sites_are_not_flagged(self, url):
        assert score_url(url)["level"] == "aman"

    @pytest.mark.parametrize("url", OFFICIAL_BRAND_DOMAINS)
    def test_official_brand_domains_are_not_flagged(self, url):
        assert score_url(url)["level"] == "aman"

    def test_keyword_inside_a_longer_word_does_not_match(self):
        # 'bri' sits inside "cambridge"; matching it there scored 65.
        findings = score_url("https://www.cambridge.org/")["findings"]
        assert findings == []

    def test_path_segment_that_merely_contains_a_keyword(self):
        # 'pos' inside "repository"
        assert score_url("https://github.com/a/repository")["score"] == 0


class TestPhishingUrls:

    @pytest.mark.parametrize("url", PHISHING)
    def test_known_patterns_are_flagged(self, url):
        assert score_url(url)["level"] in ("mencurigakan", "bahaya")

    def test_hyphen_separated_brand_still_matches(self):
        result = score_url("http://bri-mobile.tk/login")
        assert result["level"] == "bahaya"

    def test_brand_lookalike_subdomain_is_flagged(self):
        result = score_url("http://shopee.com.verify-akun.tk/")
        assert result["level"] == "bahaya"


class TestStructuralSignals:

    def test_ip_literal_host(self):
        assert "Domain berupa alamat IP (bukan nama domain)" in score_url(
            "http://192.168.1.1/"
        )["findings"]

    def test_at_sign(self):
        findings = score_url("http://example.com@evil.tk/")["findings"]
        assert any("@" in f for f in findings)

    def test_nested_url(self):
        findings = score_url("http://safe.example/?next=http://evil.tk")["findings"]
        assert any("bersarang" in f for f in findings)

    def test_deep_subdomain_nesting(self):
        findings = score_url("http://a.b.c.d.e.example.com/")["findings"]
        assert "Terlalu banyak subdomain" in findings

    def test_suspicious_tld(self):
        findings = score_url("http://something.tk/")["findings"]
        assert any("TLD mencurigakan" in f for f in findings)


class TestScoreShape:

    def test_score_is_capped_at_100(self):
        result = score_url("http://bri-bca-mandiri-bansos-hadiah.tk@evil.tk/verify")
        assert result["score"] <= 100

    def test_www_prefix_is_stripped(self):
        assert score_url("https://www.example.com/")["domain"] == "example.com"

    def test_result_keys(self):
        result = score_url("https://example.com/")
        assert set(result) == {"score", "level", "findings", "domain"}

    @pytest.mark.parametrize("level,url", [
        ("aman", "https://example.com/"),
        ("bahaya", "http://bri-mobile.tk/login"),
    ])
    def test_level_matches_score_band(self, level, url):
        assert score_url(url)["level"] == level


class TestCheckDomainReputation:

    def test_accepts_a_bare_domain(self):
        assert check_domain_reputation("example.com")["domain"] == "example.com"

    def test_accepts_a_full_url(self):
        assert check_domain_reputation("https://www.example.com/x")["domain"] == "example.com"

    def test_agrees_with_score_url(self):
        assert check_domain_reputation("bri-mobile.tk")["level"] == "bahaya"
