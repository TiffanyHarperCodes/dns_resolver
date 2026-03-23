import socket #standard Python library for network communication (used to send/receive DNS queries over UDP/TCP)
from src.dns_packet import DNSPacket


class UDPTransport:
    """
    Handles UDP communication with DNS servers.
    """

    def __init__(self, server: str, port: int = 53):
        self.server = server
        self.port = port

    def send_query(self, data: bytes) -> bytes:
        """
        Sends raw DNS query bytes and returns raw response bytes.
        """
        # with...as ensures the socket is closed automatically when the block exits,
        # even if an exception is raised — preventing socket leaks

        # socket.AF_INET -- connecting to the internet IPv4
        # socket.SOCK_DGRAM (socket datagram) -- connectionless protocol for UDP
        # the client sends each query independently with no persistent connection to the server
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
            client_socket.sendto(data, (self.server, self.port))

            # 512 bytes is the maximum payload size defined in the DNS spec (RFC 1035)
            # If a response exceeds 512 bytes, the server truncates it (i.e. cut off the response), sets a flag 
            # and sets the TC (Truncated) flag = 1, then tells the client to retry using TCP instead
            response, _ = client_socket.recvfrom(512) 
        return response