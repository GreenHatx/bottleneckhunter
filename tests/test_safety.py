import pytest

from safety import MAX_CONCURRENCY, validate_active_test


def test_active_test_requires_explicit_authorization():
    with pytest.raises(ValueError, match="authorized-target"):
        validate_active_test("https://example.com", 10)


def test_active_test_rejects_unsafe_limits():
    with pytest.raises(ValueError, match="Eszamanlilik"):
        validate_active_test("https://example.com", MAX_CONCURRENCY + 1, authorized=True)


def test_active_test_accepts_authorized_safe_limits():
    validate_active_test("https://example.com", 25, 100, authorized=True)
