import csv
import json
import time
from unittest.mock import MagicMock

import dns.resolver
import pytest
import requests

import subdomain_finder as sf


# --- load_wordlist -----------------------------------------------------

def test_load_wordlist_strips_blank_lines_and_comments(tmp_path):
    path = tmp_path / "words.txt"
    path.write_text("www\n\n# comment\napi\n  \nmail\n", encoding="utf-8")
    assert sf.load_wordlist(str(path)) == ["www", "api", "mail"]


def test_load_wordlist_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        sf.load_wordlist(str(tmp_path / "missing.txt"))


# --- RateLimiter ---------------------------------------------------------

def test_rate_limiter_disabled_does_not_block():
    limiter = sf.RateLimiter(0)
    start = time.monotonic()
    for _ in range(5):
        limiter.wait()
    assert time.monotonic() - start < 0.1


def test_rate_limiter_enforces_minimum_interval():
    limiter = sf.RateLimiter(rate=20)  # 1 slot every 0.05s
    start = time.monotonic()
    for _ in range(3):
        limiter.wait()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.1


# --- ResolverPool ---------------------------------------------------------

def test_resolver_pool_without_nameservers_returns_default_resolver():
    pool = sf.ResolverPool(None)
    resolver = pool.next_resolver()
    assert isinstance(resolver, dns.resolver.Resolver)


def test_resolver_pool_round_robins_nameservers():
    pool = sf.ResolverPool(["8.8.8.8", "1.1.1.1"])
    first = pool.next_resolver()
    second = pool.next_resolver()
    third = pool.next_resolver()
    assert first.nameservers == ["8.8.8.8"]
    assert second.nameservers == ["1.1.1.1"]
    assert third.nameservers == ["8.8.8.8"]


# --- resolve --------------------------------------------------------------

def _answer(values):
    return [MagicMock(to_text=lambda v=v: v) for v in values]


def _cname_answer(target):
    record = MagicMock()
    record.target.to_text.return_value = target
    return [record]


def test_resolve_returns_ip_when_a_record_found():
    resolver = MagicMock()

    def fake_resolve(host, record_type):
        if record_type == "A":
            return _answer(["1.2.3.4"])
        raise dns.resolver.NoAnswer()

    resolver.resolve.side_effect = fake_resolve
    result = sf.resolve("www", "example.com", resolver=resolver)
    assert result == {"host": "www.example.com", "ip": "1.2.3.4"}


def test_resolve_collects_multiple_ips_into_all_ips():
    resolver = MagicMock()

    def fake_resolve(host, record_type):
        if record_type == "A":
            return _answer(["1.1.1.1", "2.2.2.2"])
        raise dns.resolver.NoAnswer()

    resolver.resolve.side_effect = fake_resolve
    result = sf.resolve("www", "example.com", resolver=resolver)
    assert result["ip"] == "1.1.1.1"
    assert result["all_ips"] == ["1.1.1.1", "2.2.2.2"]


def test_resolve_includes_cname_when_present():
    resolver = MagicMock()

    def fake_resolve(host, record_type):
        if record_type == "CNAME":
            return _cname_answer("target.example.net.")
        if record_type == "A":
            return _answer(["5.6.7.8"])
        raise dns.resolver.NoAnswer()

    resolver.resolve.side_effect = fake_resolve
    result = sf.resolve("www", "example.com", resolver=resolver)
    assert result["cname"] == "target.example.net"
    assert result["ip"] == "5.6.7.8"


def test_resolve_returns_none_when_nxdomain_for_everything():
    resolver = MagicMock()
    resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
    result = sf.resolve("doesnotexist", "example.com", resolver=resolver)
    assert result is None


def test_resolve_returns_error_after_exhausting_retries():
    resolver = MagicMock()
    resolver.resolve.side_effect = dns.exception.Timeout()
    result = sf.resolve("slow", "example.com", retries=1, backoff=0, resolver=resolver)
    assert result["host"] == "slow.example.com"
    assert "error" in result


# --- detect_wildcard -------------------------------------------------------

def test_detect_wildcard_returns_empty_set_when_no_match():
    resolver = MagicMock()
    resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
    ips = sf.detect_wildcard("example.com", resolver=resolver, retries=0, samples=2)
    assert ips == set()


def test_detect_wildcard_returns_consistent_ip():
    resolver = MagicMock()

    def fake_resolve(host, record_type):
        if record_type == "A":
            return _answer(["9.9.9.9"])
        raise dns.resolver.NoAnswer()

    resolver.resolve.side_effect = fake_resolve
    ips = sf.detect_wildcard("example.com", resolver=resolver, retries=0, samples=3)
    assert ips == {"9.9.9.9"}


# --- fetch_crtsh_subdomains -----------------------------------------------

def test_fetch_crtsh_subdomains_parses_names(monkeypatch):
    payload = [
        {"name_value": "www.example.com\n*.api.example.com"},
        {"name_value": "mail.example.com"},
    ]
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = payload
    monkeypatch.setattr(sf.requests, "get", lambda *a, **k: response)

    labels = sf.fetch_crtsh_subdomains("example.com")
    assert labels == {"www", "api", "mail"}


def test_fetch_crtsh_subdomains_returns_empty_set_on_request_failure(monkeypatch):
    def boom(*a, **k):
        raise requests.RequestException("network down")

    monkeypatch.setattr(sf.requests, "get", boom)
    assert sf.fetch_crtsh_subdomains("example.com") == set()


# --- check_http ------------------------------------------------------------

def test_check_http_returns_first_successful_scheme(monkeypatch):
    response = MagicMock(status_code=200)
    monkeypatch.setattr(sf.requests, "get", lambda url, **k: response)
    result = sf.check_http("www.example.com")
    assert result == ("https://www.example.com", 200)


def test_check_http_returns_none_when_all_schemes_fail(monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(sf.requests, "get", boom)
    assert sf.check_http("www.example.com") is None


# --- find_subdomains_recursive ---------------------------------------------

def test_find_subdomains_recursive_deduplicates_and_recurses(monkeypatch):
    calls = []

    def fake_find_subdomains(domain, wordlist, **kwargs):
        calls.append(domain)
        if domain == "example.com":
            return [{"host": "api.example.com", "ip": "1.1.1.1"}]
        if domain == "api.example.com":
            return [{"host": "dev.api.example.com", "ip": "2.2.2.2"}]
        return []

    monkeypatch.setattr(sf, "find_subdomains", fake_find_subdomains)
    results = sf.find_subdomains_recursive("example.com", ["api"], max_depth=2, quiet=True)

    assert calls == ["example.com", "api.example.com"]
    assert {r["host"] for r in results} == {"api.example.com", "dev.api.example.com"}


def test_find_subdomains_recursive_stops_when_nothing_found(monkeypatch):
    monkeypatch.setattr(sf, "find_subdomains", lambda domain, wordlist, **kwargs: [])
    results = sf.find_subdomains_recursive("example.com", ["api"], max_depth=3, quiet=True)
    assert results == []


# --- save_results ------------------------------------------------------

SAMPLE_RESULTS = [
    {"host": "www.example.com", "ip": "1.2.3.4"},
    {"host": "alias.example.com", "ip": "5.6.7.8", "cname": "target.example.net"},
    {"host": "site.example.com", "ip": "9.9.9.9", "url": "https://site.example.com", "status": 200},
]


def test_save_results_json(tmp_path):
    path = tmp_path / "out.json"
    sf.save_results(SAMPLE_RESULTS, str(path))
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data == SAMPLE_RESULTS


def test_save_results_csv(tmp_path):
    path = tmp_path / "out.csv"
    sf.save_results(SAMPLE_RESULTS, str(path))
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert rows[0]["host"] == "www.example.com"
    assert rows[1]["cname"] == "target.example.net"
    assert rows[2]["status"] == "200"


def test_save_results_txt_includes_cname_and_http(tmp_path):
    path = tmp_path / "out.txt"
    sf.save_results(SAMPLE_RESULTS, str(path))
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "www.example.com -> 1.2.3.4"
    assert "CNAME target.example.net" in lines[1]
    assert "https://site.example.com" in lines[2] and "[200]" in lines[2]


def test_save_results_format_overrides_extension(tmp_path):
    path = tmp_path / "out.txt"
    sf.save_results(SAMPLE_RESULTS, str(path), fmt="json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data == SAMPLE_RESULTS
