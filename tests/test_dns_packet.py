import pytest
from src.dns_packet import(
_encode_name, 
DNSHeader, 
DNSQuestion, 
DNSRecord, 
DNSPacket
)


# _encode_name() -- shared module function
@pytest.mark.parametrize("domain,expected", [
    # normal domain
    ("google.com", b'\x06google\x03com\x00'),
    # long domain
    ("tiffanyharper.com", b'\x0dtiffanyharper\x03com\x00'),
    # single domain
    ("localhost", b'\x09localhost\x00'),
    # empty domain
    ("", b'\x00'),
    # root domain using dot           
    (".", b'\x00'),       
])
def test_encode_name(domain, expected):
    assert _encode_name(domain) == expected

# DNSHeader
def test_dns_header_encode():
    header = DNSHeader()
    result = header.encode()
    expected = b'\x04\xd2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    assert result == expected

# DNSQuestion
def test_dns_question_encode():
    question = DNSQuestion("google.com")
    result = question.encode()
    expected = b'\x06google\x03com\x00\x00\x01\x00\x01'
    assert result == expected

def test_dns_question_encode_tiffanyharper():
    question = DNSQuestion("tiffanyharper.com")
    result = question.encode()
    expected = b'\x0dtiffanyharper\x03com\x00\x00\x01\x00\x01'
    assert result == expected

# DNSRecord
def test_dns_record_encode():
    record = DNSRecord(
        name="google.com", 
        rtype=1, 
        rclass=1, 
        ttl=300, 
        rdata=b'\x7f\x00\x00\x01'
    )
    encoded_record = record.encode()
    # Assert domain name bytes 
    assert encoded_record.startswith(b'\x06google\x03com\x00')
    # Assert IP bytes are at the end
    assert encoded_record[-4:] == b'\x7f\x00\x00\x01'

def test_dns_record_encode_tiffanyharper():
    record = DNSRecord(
        name="tiffanyharper.com",
        rtype=1,
        rclass=1,
        ttl=600,
        rdata=b'\x08\x08\x08\x08'
    )
    encoded = record.encode()
    # Assert domain name bytes 
    assert encoded.startswith(b'\x0dtiffanyharper\x03com\x00')
    # Assert IP bytes are at the end
    assert encoded[-4:] == b'\x08\x08\x08\x08'

# DNSPacket
def test_dns_packet_encode():
    header = DNSHeader()
    question = DNSQuestion("google.com")
    packet = DNSPacket(header, [question])

    encoded_packet = packet.encode()
    # DNSPacket == header + question
    expected = header.encode() + question.encode()
    assert encoded_packet == expected

def test_dns_packet_encode_tiffanyharper():
    # Use a custom header ID to ensure test is explicit and independent
    header = DNSHeader(id=4321)
    question = DNSQuestion("tiffanyharper.com")
    packet = DNSPacket(header=header, questions=[question])
    encoded = packet.encode()
    # DNSPacket == header + question
    expected_prefix = header.encode() + question.encode()
    assert encoded == expected_prefix






