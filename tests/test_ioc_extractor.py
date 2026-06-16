from utils.ioc_extractor import extract_iocs, is_private_ip


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

