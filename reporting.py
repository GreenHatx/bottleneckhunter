"""Stable report envelope and dependency-free HTML rendering."""
import copy
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


def _label(value):
    return str(value).replace("_", " ").title()


def _summary(result):
    value = copy.deepcopy(result)

    def strip(node):
        if isinstance(node, dict):
            for key in ("raw", "samples", "rounds_data"):
                node.pop(key, None)
            for child in node.values():
                strip(child)
        elif isinstance(node, list):
            for child in node:
                strip(child)

    strip(value)
    return value


def _metric_groups(result):
    groups = []

    def walk(node, path):
        if isinstance(node, dict):
            if any(key in node for key in ("p50_ms", "p95_ms", "p99_ms")):
                groups.append((" / ".join(_label(part) for part in path), node))
                return
            for key, child in node.items():
                if key != "ai_analysis":
                    walk(child, path + [key])
        elif isinstance(node, list):
            for index, child in enumerate(node, 1):
                walk(child, path + [str(index)])

    walk(result, [])
    return groups


def _status(value, metric_name):
    if value is None:
        return "neutral"
    name = metric_name.lower()
    good, warn = (300, 1000)
    if "tls" in name:
        good, warn = (80, 250)
    elif "dns" in name:
        good, warn = (20, 80)
    elif "tcp" in name:
        good, warn = (30, 100)
    elif "server" in name or "ttfb" in name:
        good, warn = (200, 600)
    return "good" if value <= good else "warn" if value <= warn else "bad"


def _format_value(value):
    if isinstance(value, float):
        return f"{value:,.2f}"
    return str(value)


def _cards(result):
    cards = [("Test", _label(result.get("test", "run")), "neutral")]
    for key, value in result.items():
        if key.endswith("_ms") and isinstance(value, (int, float)):
            cards.append((_label(key), f"{_format_value(value)} ms", _status(value, key)))
    groups = _metric_groups(result)
    if len(cards) == 1 and groups:
        name, values = groups[0]
        value = values.get("p95_ms")
        if value is not None:
            cards.append((f"{name} P95", f"{_format_value(value)} ms", _status(value, name)))
    return cards[:6]


def _findings(result):
    findings = []
    for key, value in result.items():
        if key.endswith("_ms") and isinstance(value, (int, float)):
            findings.append(f"{_label(key)}: {_format_value(value)} ms")
        elif "breakpoint" in key and value:
            findings.append(f"{_label(key)}: {_format_value(value)}")
    if not findings:
        findings.append("Olcum tamamlandi. Ayrintili p50/p95/p99 degerleri asagidaki tablolardadir.")
    return findings


def render_comparison_html(result):
    summary = _summary(result)
    title = html.escape(_label(result.get("test", "comparison")))
    cards = "".join(
        f'<article class="card {status}"><span>{html.escape(label)}</span><strong>{html.escape(value)}</strong></article>'
        for label, value, status in _cards(summary)
    )
    findings = "".join(f"<li>{html.escape(item)}</li>" for item in _findings(summary))
    rows = []
    for name, values in _metric_groups(summary):
        p95 = values.get("p95_ms")
        rows.append(
            f'<tr class="{_status(p95, name)}"><td>{html.escape(name)}</td>'
            + "".join(f"<td>{html.escape(_format_value(values.get(key, '-')))}</td>" for key in ("n", "p50_ms", "p95_ms", "p99_ms", "mean_ms", "max_ms"))
            + "</tr>"
        )
    table = "".join(rows) or '<tr><td colspan="7">Bu test icin ozet metrik bulunamadi.</td></tr>'
    ai = summary.get("ai_analysis")
    ai_section = ""
    if ai:
        safe_ai = html.escape(str(ai)).replace("\n", "<br>")
        ai_section = f'<section><h2>AI Yorumu</h2><div class="analysis">{safe_ai}</div></section>'
    payload = html.escape(json.dumps(report_envelope(summary), ensure_ascii=False, indent=2))
    return f"""<!doctype html><html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Bottleneck Hunter - {title}</title>
<style>
:root{{--bg:#f3f6fa;--ink:#172033;--muted:#617086;--line:#dce3ec;--accent:#2855d9;--good:#14804a;--warn:#ad6800;--bad:#c42b1c}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px system-ui,sans-serif}}main{{max-width:1200px;margin:0 auto;padding:32px 20px 64px}}
header{{background:linear-gradient(135deg,#14234a,#2855d9);color:white;padding:28px;border-radius:16px}}header p{{margin-bottom:0;opacity:.8}}h1{{margin:0;font-size:30px}}h2{{margin-top:0}}
section{{background:white;margin-top:20px;padding:24px;border:1px solid var(--line);border-radius:14px;box-shadow:0 5px 18px #17305c0d}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}}
.card{{padding:16px;border:1px solid var(--line);border-left:5px solid var(--accent);border-radius:10px}}.card span{{display:block;color:var(--muted);font-size:12px;text-transform:uppercase}}.card strong{{display:block;margin-top:8px;font-size:22px}}.card.good{{border-left-color:var(--good)}}.card.warn{{border-left-color:var(--warn)}}.card.bad{{border-left-color:var(--bad)}}
.table-wrap{{overflow:auto}}table{{width:100%;border-collapse:collapse}}th,td{{padding:11px;border-bottom:1px solid var(--line);text-align:right;white-space:nowrap}}th:first-child,td:first-child{{text-align:left}}tr.good td:first-child{{color:var(--good)}}tr.warn td:first-child{{color:var(--warn)}}tr.bad td:first-child{{color:var(--bad)}}
.analysis{{line-height:1.65;border-left:4px solid var(--accent);padding:12px 16px;background:#f6f8ff}}details pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#101828;color:#dce6f5;padding:18px;border-radius:10px}}
</style></head><body><main><header><h1>Bottleneck Hunter</h1><p>{title} nihai performans raporu</p></header>
<section><h2>Yonetici Ozeti</h2><div class="grid">{cards}</div><ul>{findings}</ul></section>
<section><h2>Metrik Detaylari</h2><div class="table-wrap"><table><thead><tr><th>Metrik</th><th>N</th><th>P50 ms</th><th>P95 ms</th><th>P99 ms</th><th>Ortalama ms</th><th>Maksimum ms</th></tr></thead><tbody>{table}</tbody></table></div></section>
{ai_section}<section><details><summary>Yapilandirilmis sonuc</summary><pre>{payload}</pre></details></section>
</main></body></html>"""
