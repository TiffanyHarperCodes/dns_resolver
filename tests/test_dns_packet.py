import pytest
from src.dns_packet import(
_encode_name,
_decode_name,
DNSHeader,
DNSQuestion,
DNSRecord,
DNSPacket
)


#ENCODE

# _encode_name() -- shared module function
@pytest.mark.parametrize("domain, expected_domain", [
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
def test_encode_name(domain, expected_domain):
    assert _encode_name(domain) == expected_domain

# DNSHeader
def test_dns_header_encode():
    header = DNSHeader()
    encoded_header = header.encode()
    expected_header = b'\x04\xd2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    assert encoded_header == expected_header

# DNSQuestion
def test_dns_question_encode():
    question = DNSQuestion("google.com")
    encoded_question = question.encode()
    expected_question = b'\x06google\x03com\x00\x00\x01\x00\x01'
    assert encoded_question == expected_question

def test_dns_question_encode_tiffanyharper():
    question = DNSQuestion("tiffanyharper.com")
    encoded_question = question.encode()
    expected_question = b'\x0dtiffanyharper\x03com\x00\x00\x01\x00\x01'
    assert encoded_question == expected_question

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
    encoded_record = record.encode()
    # Assert domain name bytes 
    assert encoded_record.startswith(b'\x0dtiffanyharper\x03com\x00')
    # Assert IP bytes are at the end
    assert encoded_record[-4:] == b'\x08\x08\x08\x08'

# DNSPacket
def test_dns_packet_encode():
    header = DNSHeader()
    question = DNSQuestion("google.com")
    packet = DNSPacket(header, [question])

    encoded_packet = packet.encode()
    # DNSPacket == header + question
    expected_packet = header.encode() + question.encode()
    assert encoded_packet == expected_packet

def test_dns_packet_encode_tiffanyharper():
    # Use a custom header ID to ensure test is explicit and independent
    header = DNSHeader(id=4321)
    question = DNSQuestion("tiffanyharper.com")
    packet = DNSPacket(header=header, questions=[question])
    encoded_packet = packet.encode()
    # DNSPacket == header + question
    expected_packet = header.encode() + question.encode()
    assert encoded_packet == expected_packet


# DECODE

# _decode_name() -- shared module function
@pytest.mark.parametrize("data, expected_name, expected_offset", [
    # normal domain
    (b'\x06google\x03com\x00', "google.com", 12),
    # long domain
    (b'\x0dtiffanyharper\x03com\x00', "tiffanyharper.com", 19),
    # single domain
    (b'\x09localhost\x00', "localhost", 11),
])
def test_decode_name(data, expected_name, expected_offset):
    name, offset = _decode_name(data, 0)
    assert name == expected_name
    assert offset == expected_offset

# DNSHeader
def test_dns_header_decode():
    data = b'\x04\xd2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    header = DNSHeader.decode(data)
    assert header.id == 1234
    assert header.flags == 0x0100
    assert header.qdcount == 1
    assert header.ancount == 0
    assert header.nscount == 0
    assert header.arcount == 0

def test_dns_header_decode_too_short():
    with pytest.raises(ValueError):
        DNSHeader.decode(b'\x04\xd2\x01\x00')

# DNSQuestion
def test_dns_question_decode():
    data = b'\x06google\x03com\x00\x00\x01\x00\x01'
    # Start at 0 because we're testing question bytes in isolation (no header in front)
    question, offset = DNSQuestion.decode(data, 0)
    assert question.qname == "google.com"
    assert question.qtype == 1
    assert question.qclass == 1
    # Assert offset moved forward correctly: 12 (name) + 4 (qtype + qclass) = 16
    assert offset == 16

# DNSRecord
def test_dns_record_decode():
    record = DNSRecord(name="google.com", rtype=1, rclass=1, ttl=300, rdata=b'\x7f\x00\x00\x01')
    encoded = record.encode()
    # _ discards the offset — rdata is variable length so there's no fixed offset to assert.
    # If the values decoded correctly, the offset math was correct.
    decoded, _ = DNSRecord.decode(encoded, 0)
    assert decoded.name == "google.com"
    assert decoded.rtype == 1
    assert decoded.rclass == 1
    assert decoded.ttl == 300
    assert decoded.rdata == b'\x7f\x00\x00\x01'

# DNSPacket
def test_dns_packet_decode():
    data = b'\x04\xd2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01'
    packet = DNSPacket.decode(data)
    assert packet.header.id == 1234
    assert packet.header.qdcount == 1
    assert packet.questions[0].qname == "google.com"
    assert packet.questions[0].qtype == 1
    assert packet.questions[0].qclass == 1

def test_dns_packet_round_trip():
    # Encode and Decode the packet and verify the values match
    header = DNSHeader()
    question = DNSQuestion("google.com")
    packet = DNSPacket(header, [question])
    decoded = DNSPacket.decode(packet.encode())
    assert decoded.header.id == header.id
    assert decoded.questions[0].qname == question.qname
    assert decoded.questions[0].qtype == question.qtype
