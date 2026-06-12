from reporting import report_envelope, render_comparison_html
from bottleneck_hunter import save_report
import json


def test_report_envelope_has_versioned_schema():
    report = report_envelope({"test": "latency", "url": "https://example.com"})
    assert report["schema_version"] == "1.0"
    assert report["result"]["test"] == "latency"


def test_html_report_escapes_untrusted_values():
    page = render_comparison_html({"test": "latency", "url": "<script>alert(1)</script>"})
    assert "<script>" not in page
    assert "&lt;script&gt;" in page


def test_html_report_renders_summary_metrics_and_ai_analysis():
    page = render_comparison_html({
        "test": "latency",
        "url": "https://example.com",
        "proxy_overhead_p50_ms": 42.5,
        "modes": {
            "proxy": {
                "total": {"n": 10, "p50_ms": 350, "p95_ms": 900, "p99_ms": 1200},
                "tls": {"n": 10, "p50_ms": 120, "p95_ms": 180, "p99_ms": 220},
                "raw": [{"ok": True, "total": 0.35}],
            }
        },
        "ai_analysis": "TLS fazi incelenmeli.",
    })
    assert "Yonetici Ozeti" in page
    assert "Proxy Overhead P50" in page
    assert "Metrik Detaylari" in page
    assert "AI Yorumu" in page
    assert "TLS fazi incelenmeli." in page
    assert "&quot;raw&quot;" not in page


def test_save_report_writes_schema_json_and_html(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    json_path = save_report({"test": "latency", "raw": []}, prefix="sample")
    assert json.loads(tmp_path.joinpath(json_path).read_text())["schema_version"] == "1.0"
    assert list(tmp_path.glob("sample_latency_*.html"))
