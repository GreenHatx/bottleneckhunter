import ast
import os
from pathlib import Path

import bh_agent
import pytest


def test_agent_has_no_embedded_api_key_or_internal_endpoint():
    source = Path("bh_agent.py").read_text()
    ast.parse(source)
    assert "sk-" not in source
    assert "turktelekom.com.tr" not in source
    assert "turktelekom.intra" not in source
    assert "BOTTLENECK_LLM_API_KEY" in source


def test_load_dotenv_uses_agent_directory_and_preserves_environment(monkeypatch):
    calls = []
    monkeypatch.setenv("BOTTLENECK_LLM_API_KEY", "system-key")
    monkeypatch.setattr(bh_agent, "load_dotenv", lambda path, override: calls.append((path, override)))

    bh_agent.load_ai_environment()

    assert calls == [(bh_agent.DOTENV_PATH, False)]
    assert os.environ["BOTTLENECK_LLM_API_KEY"] == "system-key"


def test_missing_ai_settings_error_names_expected_dotenv_path(monkeypatch):
    monkeypatch.delenv("BOTTLENECK_LLM_BASE_URL", raising=False)
    monkeypatch.delenv("BOTTLENECK_LLM_API_KEY", raising=False)
    monkeypatch.setattr(bh_agent, "load_ai_environment", lambda: None)
    monkeypatch.setattr(bh_agent, "llm_base", None)

    with pytest.raises(RuntimeError, match=r"BOTTLENECK_LLM_BASE_URL.*BOTTLENECK_LLM_API_KEY.*\.env"):
        bh_agent.configure_llm()
