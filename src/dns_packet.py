from dataclasses import dataclass
from typing import List


@dataclass
class DNSHeader:
    id: int
    flags: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int


class DNSQuestion:
    """
    DNS Question Section
    """

    def __init__(self, qname: str, qtype: int, qclass: int):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass


class DNSPacket:
    """
    Responsible for encoding and decoding DNS packets.
    """

    def __init__(self, header: DNSHeader, questions: List[DNSQuestion]):
        self.header = header
        self.questions = questions

    def encode(self) -> bytes:
        """
        Serialize packet to bytes for sending over the network.
        """
        raise NotImplementedError

    @classmethod
    def decode(cls, data: bytes) -> "DNSPacket": #avoid NameError 
        """
        Deserialize bytes received from network into DNSPacket.
        """
        raise NotImplementedError