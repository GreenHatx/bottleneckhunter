"""Dependency-free AI API health-check helpers."""

import time


def check_ai_connection(connector, model):
    """Run a minimal request and classify connection or authentication failures."""
    started = time.monotonic()
    try:
        response = connector()
        content = str(response or "").strip()
        if not content:
            raise RuntimeError("AI endpoint bos yanit dondurdu")
        return {
            "ok": True,
            "model": model,
            "latency_ms": round((time.monotonic() - started) * 1000),
            "response": content[:100],
        }
    except Exception as exc:
        message = str(exc)
        lowered = message.lower()
        category = "authentication" if any(
            marker in lowered for marker in ("401", "403", "auth", "api key")
        ) else "connection"
        return {"ok": False, "category": category, "error": message}


def print_ai_check(result):
    """Print the AI health-check result and return a shell-friendly exit code."""
    if result["ok"]:
        print(
            "AI API baglantisi basarili | "
            f"model={result['model']} | latency={result['latency_ms']} ms"
        )
        return 0
    print(
        "AI API baglantisi basarisiz | "
        f"kategori={result['category']} | hata={result['error']}"
    )
    return 1
