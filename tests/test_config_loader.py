import json

import pytest

from config_loader import expand_config_args, load_config


def write_config(tmp_path, data):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data))
    return str(path)


def test_config_expands_command_common_and_parameters(tmp_path):
    path = write_config(tmp_path, {
        "command": "latency",
        "common": {"proxy": "http://proxy:8080", "no_save": True},
        "parameters": {"url": "https://example.com", "repeat": 5},
    })
    args = expand_config_args(["--config", path])
    assert args == ["latency", "--proxy", "http://proxy:8080", "--no-save", "--url", "https://example.com", "--repeat", "5"]


def test_explicit_cli_values_are_appended_last_and_override_config(tmp_path):
    path = write_config(tmp_path, {"command": "latency", "parameters": {"url": "https://config", "repeat": 5}})
    args = expand_config_args(["--config", path, "--repeat", "9"])
    assert args[-2:] == ["--repeat", "9"]


def test_config_rejects_unknown_command(tmp_path):
    path = write_config(tmp_path, {"command": "destroy", "parameters": {}})
    with pytest.raises(ValueError, match="command"):
        load_config(path)
