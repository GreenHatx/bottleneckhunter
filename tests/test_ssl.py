import bottleneck_hunter as bh


def test_ssl_supports_transparent_proxy_without_explicit_address(monkeypatch):
    sample = bh.Sample(ok=True, tls=0.1, total=0.2)
    monkeypatch.setattr(bh, "do_request", lambda *args, **kwargs: sample)

    result = bh.test_ssl("https://inspected.example", "https://bypass.example", bh.ProxyConfig(), repeat=1)

    assert result["proxy_mode"] == "transparent"


def test_ssl_does_not_report_zero_when_all_requests_fail(monkeypatch, capsys):
    cfg = bh.ProxyConfig(proxy="http://proxy:8080")
    monkeypatch.setattr(bh, "do_request", lambda *args, **kwargs: bh.Sample(ok=False, err="offline"))

    result = bh.test_ssl("https://inspected.example", "https://bypass.example", cfg, repeat=1)

    assert "inspection_tls_overhead_p50_ms" not in result
    assert "olculemedi" in capsys.readouterr().out


def test_ssl_does_not_treat_zero_tls_timing_as_zero_inspection_cost(monkeypatch):
    sample = bh.Sample(ok=True, tls=0.0, total=0.2)
    monkeypatch.setattr(bh, "do_request", lambda *args, **kwargs: sample)

    result = bh.test_ssl("https://inspected.example", "https://bypass.example", bh.ProxyConfig(), repeat=1)

    assert "inspection_tls_overhead_p50_ms" not in result
    assert "inspection_warning" in result
