from config_loader import load_config


def test_example_config_documents_complete_full_workflow():
    config = load_config("bottleneck.config.example.json")

    assert config["command"] == "full"
    assert config["common"]["proxy"] is None
    assert config["common"]["authorized_target"] is False
    assert set(config["tests"]) == {
        "latency", "ssl", "load", "throughput", "cache", "soak", "stress", "browser", "full",
    }
    assert config["tests"]["ssl"]["bypass_url"] == "https://www.microsoft.com"
    assert config["tests"]["full"]["url"] == config["tests"]["latency"]["url"]
