import pytest

import bottleneck_hunter as bh


def test_ssl_requires_proxy():
    with pytest.raises(ValueError, match="proxy"):
        bh.test_ssl("https://inspected.example", "https://bypass.example", bh.ProxyConfig(), repeat=1)


def test_ssl_does_not_report_zero_when_all_requests_fail(monkeypatch, capsys):
    cfg = bh.ProxyConfig(proxy="http://proxy:8080")
    monkeypatch.setattr(bh, "do_request", lambda *args, **kwargs: bh.Sample(ok=False, err="offline"))

    result = bh.test_ssl("https://inspected.example", "https://bypass.example", cfg, repeat=1)

    assert "inspection_tls_overhead_p50_ms" not in result
    assert "olculemedi" in capsys.readouterr().out
