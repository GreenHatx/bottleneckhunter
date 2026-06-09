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


def test_save_report_writes_schema_json_and_html(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    json_path = save_report({"test": "latency", "raw": []}, prefix="sample")
    assert json.loads(tmp_path.joinpath(json_path).read_text())["schema_version"] == "1.0"
    assert list(tmp_path.glob("sample_latency_*.html"))
