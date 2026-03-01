import socket


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
        raise NotImplementedError