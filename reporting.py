"""Stable report envelope and dependency-free HTML rendering."""
import html
import json
from datetime import datetime, timezone

SCHEMA_VERSION = "1.0"


def report_envelope(result):
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "bottleneckhunter",
        "result": result,
    }


def render_comparison_html(result):
    payload = html.escape(json.dumps(report_envelope(result), ensure_ascii=False, indent=2))
    title = html.escape(str(result.get("test", "comparison")).title())
    return f"""<!doctype html><html lang="tr"><meta charset="utf-8">
<title>Bottleneck Hunter - {title}</title>
<style>body{{font:15px system-ui;max-width:1100px;margin:32px auto;padding:0 20px;color:#172033}}pre{{background:#f4f6f8;padding:20px;overflow:auto;border:1px solid #d8dee6}}h1{{font-size:24px}}</style>
<h1>Bottleneck Hunter - {title}</h1><p>Standart rapor semasi: {SCHEMA_VERSION}</p><pre>{payload}</pre></html>"""
