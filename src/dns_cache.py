import time


class DNSCache:
    """
    Simple in-memory cache with TTL support.
    """

    def __init__(self):
        self._store = {}

    def get(self, key):
        raise NotImplementedError

    def set(self, key, value, ttl: int):
        raise NotImplementedError
