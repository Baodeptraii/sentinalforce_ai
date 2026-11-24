"""Bound real HTTP response reads by size and an absolute monotonic deadline."""
import time
from http.client import HTTPResponse
from urllib.error import HTTPError


def read_limited(response, limit, deadline):
    if not isinstance(response, (HTTPResponse, HTTPError)):
        return response.read(limit + 1)  # Explicit fixture/test adapter.
    chunks = []; size = 0
    while size <= limit:
        if time.monotonic() >= deadline: raise TimeoutError('HTTP body deadline exceeded')
        data = response.read1(min(16384, limit + 1 - size))
        if not data: break
        chunks.append(data); size += len(data)
    return b''.join(chunks)
