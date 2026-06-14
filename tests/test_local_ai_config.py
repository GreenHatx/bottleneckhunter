import os

import bh_agent


def test_local_python_config_supplies_ai_settings(monkeypatch):
    monkeypatch.delenv("BOTTLENECK_LLM_MODEL", raising=False)
    monkeypatch.delenv("BOTTLENECK_LLM_BASE_URL", raising=False)
    monkeypatch.delenv("BOTTLENECK_LLM_API_KEY", raising=False)
    monkeypatch.setattr(bh_agent, "load_dotenv", lambda *args, **kwargs: None)
    monkeypatch.setattr(bh_agent, "load_local_ai_config", lambda: {
        "BOTTLENECK_LLM_MODEL": "local-model",
        "BOTTLENECK_LLM_BASE_URL": "https://local.example/v1",
        "BOTTLENECK_LLM_API_KEY": "local-key",
    })

    bh_agent.load_ai_environment()

    assert os.environ["BOTTLENECK_LLM_MODEL"] == "local-model"
    assert os.environ["BOTTLENECK_LLM_BASE_URL"] == "https://local.example/v1"
    assert os.environ["BOTTLENECK_LLM_API_KEY"] == "local-key"


def test_environment_overrides_local_python_config(monkeypatch):
    monkeypatch.setenv("BOTTLENECK_LLM_API_KEY", "system-key")
    monkeypatch.setattr(bh_agent, "load_dotenv", lambda *args, **kwargs: None)
    monkeypatch.setattr(bh_agent, "load_local_ai_config", lambda: {"BOTTLENECK_LLM_API_KEY": "local-key"})

    bh_agent.load_ai_environment()

    assert os.environ["BOTTLENECK_LLM_API_KEY"] == "system-key"
