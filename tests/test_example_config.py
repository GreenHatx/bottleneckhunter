from config_loader import load_config


def test_example_config_documents_complete_full_workflow():
    config = load_config("bottleneck.config.example.json")

    assert config["command"] == "full"
    assert config["common"]["proxy"] is None
    assert config["common"]["authorized_target"] is False
    assert set(config["parameters"]) == {
        "url", "repeat", "bypass_url", "throughput_url", "levels", "requests",
        "cache_rounds", "browser", "soak", "soak_interval",
    }
