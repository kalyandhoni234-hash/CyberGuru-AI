from utils.ioc_extractor import (
    extract_iocs,
    extract_all_ips,
    extract_domains,
    extract_hashes,
    ip_scope,
    is_private_ip,
)


def test_private_ips_are_not_queryable_iocs():
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("10.0.0.5") is True
    assert is_private_ip("8.8.8.8") is False


def test_extract_iocs_filters_private_ips_and_deduplicates_values():
    result = extract_iocs(
        "Seen 8.8.8.8 and 10.0.0.5. Visit https://example.com/a twice "
        "https://example.com/a or email analyst@example.com analyst@example.com"
    )

    assert result["ips"] == ["8.8.8.8"]
    assert result["urls"] == ["https://example.com/a"]
    assert result["emails"] == ["analyst@example.com"]
    assert result["domains"] == ["example.com"]
    assert result["hashes"] == []


def test_extract_iocs_can_keep_private_ips():
    result = extract_iocs(
        "Beaconing from 10.0.0.5 to 8.8.8.8", include_private_ips=True
    )
    assert result["ips"] == ["10.0.0.5", "8.8.8.8"]


def test_ip_scope_marks_testnet_as_documentation():
    assert ip_scope("192.0.2.1") == "documentation"
    assert ip_scope("198.51.100.42") == "documentation"
    assert ip_scope("203.0.113.77") == "documentation"
    assert ip_scope("8.8.8.8") == "global"
    assert ip_scope("10.0.0.5") == "private"
    assert ip_scope("127.0.0.1") == "loopback"
    assert ip_scope("not-an-ip") == "invalid"


def test_extract_all_ips_keeps_every_scope_in_order():
    assert extract_all_ips(
        "connect to 198.51.100.42 or 8.8.8.8 then 192.168.1.1"
    ) == ["198.51.100.42", "8.8.8.8", "192.168.1.1"]


def test_extract_domains_deduplicates_case_insensitively():
    assert extract_domains(
        "c2.evil.org followed by sub.evil.org and EVIL.ORG"
    ) == ["c2.evil.org", "sub.evil.org", "evil.org"]


def test_extract_hashes_returns_sha256_and_md5():
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    assert extract_hashes(f"{sha256} and {md5} and not-a-hash") == [sha256, md5]
