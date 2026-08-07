from kwara.utils.domain import extract_domain_from_url


def test_extract_registrable_domain_from_https_url():
    d = extract_domain_from_url("https://www.google.com/search?q=test")
    assert d == "google.com"


def test_empty_returns_empty():
    assert extract_domain_from_url("") == ""
