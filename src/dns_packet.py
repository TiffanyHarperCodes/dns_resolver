from dataclasses import dataclass
from typing import List
import struct #standard library for packing Python values into raw bytes (used for the wire format)


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

    def decode_header(self):
        """
        Deserialize raw bytes into a DNSHeader instance.
        """
        raise NotImplementedError

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

    def decode(self, data: bytes, offset: int) -> tuple[DNSQuestion, int]:
        """
        Deserialize raw bytes into a DNSQuestion instance starting at offset.
        Returns the decoded question and the new offset position.
        """
        raise NotImplementedError


@dataclass
class DNSRecord:  # DNS Resource Record
    name: str  
    rtype: int    # 2 bytes
    rclass: int   # 2 bytes -- resource record class (usually IN = 1 for Internet)
    ttl: int      # 4 bytes (I = 32-bit unsigned integer)
    rdata: bytes  # variable -- actual value of the record (format depends on type: A, AAAA, NS, etc.)
                  # variable length data; actual size depends on rtype, rdlength = len(rdata) 
    

    def encode(self):
        """
        Serialize the resource record into bytes.
        Returns the encoded name, followed by rtype, rclass, ttl, rdlength, and rdata.
        """
        encoded_name = _encode_name(self.name)
        rdlength = len(self.rdata)

        return (
            encoded_name +
            struct.pack("!2HIH", self.rtype, self.rclass, self.ttl, rdlength) +
            self.rdata
        )

    @classmethod
    def decode(cls, data: bytes, offset: int) -> tuple[DNSRecord, int]:
        """
        Deserialize raw bytes into a DNSRecord instance starting at offset.
        Returns the decoded record and the new offset position.
        """
        raise NotImplementedError


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

    def encode(self) -> bytes:
        """
        Serialize the full DNS packet into bytes.
        Returns the encoded header followed by all encoded questions.
        """
        return self.header.encode() + b"".join(q.encode() for q in self.questions)
         # RESULT:
         #b'\x04\xd2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01'           
    

    @classmethod
    def decode(cls, data: bytes) -> "DNSPacket":
        """
        Deserialize bytes received from network into DNSPacket.
        """
        raise NotImplementedError


def _encode_name(domain: str) -> bytes:
    if not domain or domain == ".":
        return b'\x00'
    # "google.com" -> \x06google\x03com\x00
    labels = b""
    for part in domain.split("."):
        encoded = part.encode() # Python's built-in str.encode() which converts a string to bytes using UTF-8 by default (e.g. "google" --> b"google")
        labels += bytes([len(encoded)]) + encoded
    return labels + b"\x00"  


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """
    Deserialize a length-prefixed DNS name from raw bytes starting at offset.
    Returns the decoded domain string and the new offset position.
    """
    raise NotImplementedError