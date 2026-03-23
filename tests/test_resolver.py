from src.resolver import DNSResolver


# DNSResolver.build_query
def test_build_query_returns_bytes():
    # build_query should return raw bytes ready to send over the network
    result = DNSResolver.build_query("google.com")
    assert isinstance(result, bytes)

def test_build_query_header_length():
    # the first 12 bytes are always the DNS header
    result = DNSResolver.build_query("google.com")
    assert len(result) >= 12

def test_build_query_encodes_normal_domain():
    # encoded domain name should appear in the query after the 12-byte header
    result = DNSResolver.build_query("google.com")
    assert b'\x06google\x03com\x00' in result

def test_build_query_encodes_long_domain():
    # encoded domain name should appear in the query after the 12-byte header
    result = DNSResolver.build_query("tiffanyharper.com")
    assert b'\x0dtiffanyharper\x03com\x00' in result

def test_build_query_encodes_single_domain():
    # encoded domain name should appear in the query after the 12-byte header
    result = DNSResolver.build_query("localhost")
    assert b'\x09localhost\x00' in result
