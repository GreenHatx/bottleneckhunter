import ast
from pathlib import Path


def test_agent_has_no_embedded_api_key_or_internal_endpoint():
    source = Path("bh_agent.py").read_text()
    ast.parse(source)
    assert "sk-" not in source
    assert "turktelekom.com.tr" not in source
    assert "turktelekom.intra" not in source
    assert "BOTTLENECK_LLM_API_KEY" in source
