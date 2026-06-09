"""Safety limits for active load and stress tests."""
from urllib.parse import urlparse

MAX_CONCURRENCY = 200
MAX_REQUESTS_PER_LEVEL = 1000


def validate_active_test(url, concurrency, requests_per_level=None, authorized=False):
    host = urlparse(url).hostname
    if not host:
        raise ValueError("Gecerli bir hedef URL gerekli")
    if not authorized:
        raise ValueError("Aktif yuk testleri icin --authorized-target onayi gerekli")
    if concurrency < 1 or concurrency > MAX_CONCURRENCY:
        raise ValueError(f"Eszamanlilik 1-{MAX_CONCURRENCY} araliginda olmali")
    if requests_per_level is not None and not 1 <= requests_per_level <= MAX_REQUESTS_PER_LEVEL:
        raise ValueError(f"Seviye basina istek 1-{MAX_REQUESTS_PER_LEVEL} araliginda olmali")
