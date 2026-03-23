from dataclasses import dataclass
from typing import List
import struct #standard library for packing Python values into raw bytes (used for the wire format)
import logging

logger = logging.getLogger(__name__)


@dataclass                   # Header = Control Information
class DNSHeader:             # The first 12 bytes of every DNS Packet.                             
    id: int = 1234           #0-1 bytes (Unique ID used to match a response with the original query)
    flags: int = 0x0100      #2-3 bytes (RD = 1; Recursion Desired -- asking the DNS server to perform recursive resolution for this query)
    qdcount: int = 1         #4-5 bytes (the number of entries in the Question section)
    ancount: int = 0         #6-7 bytes (the number of answer records)
    nscount: int = 0         #8-9 bytes (the number of authority records)
    arcount: int = 0         #10-11 bytes (the number of additional records)
    
    def encode(self) -> bytes:
        """
        Serialize packet to bytes for sending over the network.
        """
        return struct.pack(
            "!6H",
            self.id,
            self.flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount
        )
        # RESULT:
        # b'\x04\xd2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'

    @classmethod
    def decode(cls, data: bytes) -> "DNSHeader":
        """
        Deserialize raw bytes into a DNSHeader instance.
        """
        if len(data) < 12: #Headers are always the first 12 bytes of every DNS Packet
            raise ValueError("Data too short to contain a DNS header")
        id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!6H", data[:12])
        return cls(id, flags, qdcount, ancount, nscount, arcount)


@dataclass
class DNSQuestion: # Question Section = What Is Being Asked
    """
    DNS Question Section
    """
    qname: str
    qtype: int = 1
    qclass: int = 1

    def encode(self) -> bytes:
        """
        Serialize the question section into bytes.
        Returns the encoded domain name followed by the 2-byte qtype and 2-byte qclass.
        """
        return _encode_name(self.qname) + struct.pack("!2H", self.qtype, self.qclass) 
    # RESULT:
    # b'\x06google\x03com\x00\x00\x01\x00\x01'
    
    #  \x00  =  0  (high byte)                                                                                                                                                     
    #  \x01  =  1  (low byte)
                                                                                                                                                                                
    #  struct.pack("!H", 1) packs the integer 1 as a 2-byte big-endian unsigned short. 
    #  Since 1 fits in one byte, the high byte is 0x00 and the low byte is 0x01 — 
    #  together they represent the 16-bit value 1.

    #  \x00\x01 on the wire = the integer 1 in Python

    @classmethod
    def decode(cls, data: bytes, offset: int) -> tuple["DNSQuestion", int]:
        """
        Deserialize raw bytes into a DNSQuestion instance starting at offset.
        Returns the decoded question and the new offset position.
        """
        qname, offset = _decode_name(data, offset)
        qtype, qclass = struct.unpack("!2H", data[offset : offset + 4]) #q type + qclass == 4 bytes
        offset += 4 # Point the offset to the next field
        return cls(qname, qtype, qclass), offset


@dataclass
class DNSRecord:  # DNS Resource Record
    name: str  
    rtype: int    # 2 bytes
    rclass: int   # 2 bytes -- resource record class (usually IN = 1 for Internet)
    ttl: int      # 4 bytes (I = 32-bit unsigned integer)
    rdata: bytes  # variable -- actual value of the record (format depends on type: A, AAAA, NS, etc.)
                  # variable length data; actual size depends on rtype, rdlength = len(rdata) 
    
    def encode(self) -> bytes:
        """
        Serialize the resource record into bytes.
        Returns the encoded name, followed by rtype, rclass, ttl, rdlength, and rdata.
        """
        rdlength = len(self.rdata)

        return (
            _encode_name(self.name) +
            struct.pack("!2HIH", self.rtype, self.rclass, self.ttl, rdlength) +
            self.rdata
        )

    @classmethod
    def decode(cls, data: bytes, offset: int) -> tuple[DNSRecord, int]:
        """
        Deserialize raw bytes into a DNSRecord instance starting at offset.
        Returns the decoded record and the new offset position.
        """
        name, offset = _decode_name(data, offset)

        rtype, rclass, ttl, rdlength = struct.unpack("!2HIH", data[offset : offset + 10]) #rtype + rclass + ttl + rdlength == 10 bytes
        offset += 10 # Point the offset to the next field

        rdata = data[offset : offset + rdlength] # the actual payload -- since rdata varies depending on rtype, use the offset and rdlength to know where rdata ends
        offset += rdlength
        return cls(name, rtype, rclass, ttl, rdata), offset


class DNSPacket:
    """
    Responsible for encoding and decoding DNS packets.
    """
    def __init__(
            self, 
            header: DNSHeader, 
            questions: List[DNSQuestion], 
            answers=None, 
            authorities=None, 
            additionals=None
        ):
        self.header = header
        self.questions = questions
        self.answers = answers or []  #DNSRecord[]
        self.authorities = authorities or [] #DNSRecord[]
        self.additionals = additionals or []  #DNSRecord[]

    def __repr__(self):
        return (
            f"DNSPacket(\n"
            f"  header={self.header},\n"
            f"  questions={self.questions},\n"
            f"  answers={self.answers},\n"
            f"  authorities={self.authorities},\n"
            f"  additionals={self.additionals}\n"
            f")"
    )

    def encode(self) -> bytes:
        """
        Serialize the full DNS packet into bytes.
        Returns the encoded header followed by all encoded questions.
        """
        return self.header.encode() + b"".join(q.encode() for q in self.questions)
         # RESULT:
         #b'\x04\xd2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01'           
    
    @classmethod
    def decode(cls, data: bytes) -> DNSPacket:
        """
        Deserialize bytes received from network into DNSPacket.
        """
        logger.debug(f"Raw bytes received: {data}")

        header = DNSHeader.decode(data)
        logger.debug(f"Decoded header: {header}")

        question, offset = DNSQuestion.decode(data, 12)
        logger.debug(f"Decoded question: {question}")
        logger.debug(f"Offset after question: {offset}")

        questions = [question]
        logger.debug(f"Final packet — header: {header}, questions: {questions}")

        return cls(header, questions)
    

def _encode_name(domain: str) -> bytes:
    if not domain or domain == ".":
        return b'\x00'
    # "google.com" -> \x06google\x03com\x00
    labels = b""
    for part in domain.split("."):
        encoded = part.encode() # Python's built-in str.encode() converts a string to bytes using UTF-8 by default (e.g. "google" --> b"google")
        labels += bytes([len(encoded)]) + encoded
    return labels + b"\x00"  


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """
    Deserialize a length-prefixed DNS name from raw bytes starting at offset.
    Returns the decoded domain string and the new offset position.
    """
    labels = [] 

    while data[offset] != 0: # Loop until we hit the terminator byte (0x00)
        length = data[offset] # Length of the current label
        # Slice the label bytes and decode to string, then append to labels
        labels.append(data[offset + 1 : offset + 1 + length].decode()) # Python’s built-in bytes.decode() converts a bytes object into a string using UTF-8 by default (e.g., b"google" -> "google")
        offset += 1 + length  # Move offset past length byte and the label itself

    offset += 1 # Skip past the terminator byte (0x00) so the next field starts correctly
    return ".".join(labels), offset







