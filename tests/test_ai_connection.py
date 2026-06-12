import ai_health


def test_ai_connection_check_reports_success():
    result = ai_health.check_ai_connection(lambda: "OK", "test-model")

    assert result["ok"] is True
    assert result["response"] == "OK"
    assert result["latency_ms"] >= 0


def test_ai_connection_check_classifies_authentication_error():
    def fail():
        raise RuntimeError("401 invalid API key")

    result = ai_health.check_ai_connection(fail, "test-model")

    assert result == {
        "ok": False,
        "category": "authentication",
        "error": "401 invalid API key",
    }


def test_ai_connection_check_rejects_empty_response():
    result = ai_health.check_ai_connection(lambda: "", "test-model")

    assert result["ok"] is False
    assert "bos yanit" in result["error"]
