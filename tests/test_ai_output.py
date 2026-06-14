import bh_agent


def test_clean_ai_output_removes_think_block():
    output = bh_agent.clean_ai_output("<think>internal reasoning</think>\nDarbogaz TLS fazinda.")

    assert output == "Darbogaz TLS fazinda."


def test_clean_ai_output_preserves_normal_response():
    assert bh_agent.clean_ai_output("Normal yorum") == "Normal yorum"
