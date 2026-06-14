import ast
import os
from pathlib import Path

import bh_agent


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

    assert calls == [(Path(bh_agent.__file__).with_name(".env"), False)]
    assert os.environ["BOTTLENECK_LLM_API_KEY"] == "system-key"
