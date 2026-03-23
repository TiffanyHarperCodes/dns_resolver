from src.dns_packet import DNSHeader, DNSQuestion, DNSPacket
from src.transport import UDPTransport


class DNSResolver:
    """
    High-level DNS resolution logic.

    Currently implements only UDP-based resolution.
    """

    def __init__(self, server: str = "8.8.8.8"): # Google public DNS server
        self.transport = UDPTransport(server)
    

    @staticmethod
    def build_query(domain: str) -> bytes:
        """
        Build DNS packet to be sent over the network.
        """
        header = DNSHeader()
        question = DNSQuestion(domain)
        packet = DNSPacket(header, [question])
        return packet.encode()


    def resolve(self, domain: str) -> DNSPacket:
        """
        Resolve a domain name to its DNS response packet.
        """
        query = self.build_query(domain)
        response = self.transport.send_query(query)
        return DNSPacket.decode(response)
    