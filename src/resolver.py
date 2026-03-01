from src.dns_packet import DNSPacket
from src.transport import UDPTransport


class DNSResolver:
    """
    High-level DNS resolution logic.

    Currently implements only UDP-bsed resolution.
    """

    def __init__(self, server: str = "8.8.8.8"):
        self.transport = UDPTransport(server)

    def resolve(self, domain: str) -> DNSPacket:
        """
        Resolve a domain name to its DNS response packet.
        """
        raise NotImplementedError

