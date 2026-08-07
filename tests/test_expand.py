from pantau.expand import is_shortener


def test_exact_shortener_hostname_matches():
    assert is_shortener("bit.ly")


def test_shortener_subdomain_matches():
    assert is_shortener("go.bit.ly:443")


def test_shortener_text_inside_unrelated_domain_does_not_match():
    assert not is_shortener("not-bit.ly.example.com")
    assert not is_shortener("orbit.ly")


def test_full_url_is_normalized_to_hostname():
    assert is_shortener("https://BIT.LY/path")
