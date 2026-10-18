import pytest

from kestrix.core.errors import Reason, Rejected
from kestrix.forensics.url import MAX_URL_CHARS, analyze_url

CYRILLIC_A = chr(0x0430)
RU_HOST = "".join(map(chr, [0x043F, 0x0440, 0x0438, 0x043C, 0x0435, 0x0440])) + "." + chr(0x0440) + chr(0x0444)


def ids(url: str) -> set[str]:
    return {finding.id for finding in analyze_url(url).findings}


@pytest.mark.parametrize(
    ("url", "finding_id"),
    [
        ("http://192.168.10.5/login", "ip_address_host"),
        ("http://3232235777/", "ip_address_host"),
        ("http://[2001:db8::1]/", "ip_address_host"),
        ("https://www.paypal.com@evil.example/", "userinfo_in_url"),
        (f"https://p{CYRILLIC_A}ypal.com/", "mixed_script_host"),
        (f"https://{RU_HOST}/", "international_host"),
        ("https://a.b.c.d.example.com/", "many_subdomains"),
        ("https://free-prizes.xyz/", "suspicious_tld"),
        ("https://bit.ly/3abcDEF", "url_shortener"),
        ("https://paypal.com.account-check.net/", "brand_in_subdomain"),
        ("https://paypal-secure.com/", "brand_in_domain"),
        ("https://example.com/" + "a" * 120, "long_url"),
        ("http://example.com/", "not_https"),
        ("https://example.com:8443/", "unusual_port"),
        ("https://example.com/account/verify", "suspicious_keywords"),
    ],
)
def test_signal_fires(url: str, finding_id: str) -> None:
    assert finding_id in ids(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://www.google.com/",
        "https://news.bbc.co.uk/sport",
        "https://www.mail.example.com/",
        "https://example.com:443/",
        "example.org/docs",
    ],
)
def test_ordinary_urls_score_zero(url: str) -> None:
    report = analyze_url(url)
    assert report.findings == []
    assert report.score == 0
    assert report.level == "none"


def test_brand_on_its_own_domain_is_not_flagged() -> None:
    found = ids("https://accounts.google.com/signin")
    assert not found & {"brand_in_subdomain", "brand_in_domain"}
    assert found == {"suspicious_keywords"}


def test_homograph_host_is_reported_in_both_forms() -> None:
    report = analyze_url(f"https://p{CYRILLIC_A}ypal.com/login")
    assert report.host.startswith("xn--")
    assert report.unicode_host == f"p{CYRILLIC_A}ypal.com"
    assert report.findings[0].severity == "high"


def test_international_name_without_mixing_is_medium() -> None:
    report = analyze_url(f"https://{RU_HOST}/")
    assert report.unicode_host == RU_HOST
    assert [(f.id, f.severity) for f in report.findings] == [("international_host", "medium")]


def test_report_fields() -> None:
    report = analyze_url("  https://News.BBC.co.uk./  ")
    assert report.url == "https://News.BBC.co.uk./"
    assert report.scheme == "https"
    assert report.host == "news.bbc.co.uk"
    assert report.registrable_domain == "bbc.co.uk"
    assert "not a probability" in report.score_note


def test_scheme_less_url_is_not_called_insecure() -> None:
    report = analyze_url("example.com/login")
    assert report.scheme is None
    assert "not_https" not in {f.id for f in report.findings}


def test_ip_host_has_no_registrable_domain() -> None:
    assert analyze_url("http://10.0.0.1/").registrable_domain is None


def test_keyword_weight_is_capped() -> None:
    few = analyze_url("https://example.com/login")
    many = analyze_url("https://example.com/login/verify/account/password/billing")
    assert few.score == 5
    assert many.score == 15


def test_score_bands_and_cap() -> None:
    low = analyze_url("http://example.com/")
    medium = analyze_url(f"https://p{CYRILLIC_A}ypal.com/")
    high = analyze_url("http://paypal.com.verify-account.xyz@198.51.100.7:8080/login/verify/account/" + "x" * 80)
    assert (low.score, low.level) == (10, "low")
    assert (medium.score, medium.level) == (50, "medium")  # mixed script + imitates "paypal"
    assert high.level == "high"
    assert high.score <= 100
    assert high.findings[0].severity == "high"


@pytest.mark.parametrize(
    "url",
    ["", "   ", "ftp://example.com/", "javascript:alert(1)", "https://", "http://a b.com/", "https://e.com:99999/"],
)
def test_invalid_urls_are_rejected(url: str) -> None:
    with pytest.raises(Rejected) as excinfo:
        analyze_url(url)
    assert excinfo.value.reason is Reason.INVALID_URL


def test_oversized_url_is_rejected() -> None:
    with pytest.raises(Rejected) as excinfo:
        analyze_url("https://example.com/" + "a" * MAX_URL_CHARS)
    assert excinfo.value.reason is Reason.INPUT_TOO_LARGE


@pytest.mark.parametrize(
    ("url", "finding"),
    [
        ("http://paypa1-login.example.top/", "brand_in_subdomain"),
        ("https://g00gle.com/", "brand_in_domain"),
        ("https://micros0ft-support.com/", "brand_in_domain"),
        ("https://arnazon-billing.net/", "brand_in_domain"),
    ],
)
def test_typo_squatted_brands(url: str, finding: str) -> None:
    assert finding in {f.id for f in analyze_url(url).findings}


@pytest.mark.parametrize("url", ["https://www.paypal.com/signin", "https://github.com/", "https://example.org/"])
def test_genuine_hosts_are_not_brand_flagged(url: str) -> None:
    assert not {f.id for f in analyze_url(url).findings} & {"brand_in_subdomain", "brand_in_domain"}
