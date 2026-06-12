"""Load Bottleneck Hunter CLI arguments from a JSON config file."""
import json
from pathlib import Path

COMMANDS = {"latency", "ssl", "load", "throughput", "cache", "soak", "stress", "browser", "full"}


def load_config(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Config kok degeri JSON nesnesi olmali")
    command = data.get("command")
    if command not in COMMANDS:
        raise ValueError("Config icinde gecerli bir 'command' gerekli")
    return data


def _option_args(values):
    args = []
    for key, value in values.items():
        if value is None or value is False:
            continue
        flag = "--" + key.replace("_", "-")
        if value is True:
            args.append(flag)
        elif isinstance(value, list):
            if key == "header":
                for item in value:
                    args.extend([flag, str(item)])
            else:
                args.extend([flag, ",".join(str(item) for item in value)])
        else:
            args.extend([flag, str(value)])
    return args


def expand_config_args(argv):
    """Expand --config into CLI arguments; explicit CLI values win."""
    if "--config" not in argv:
        return argv
    index = argv.index("--config")
    try:
        path = argv[index + 1]
    except IndexError as exc:
        raise ValueError("--config icin dosya yolu gerekli") from exc
    remaining = argv[:index] + argv[index + 2:]
    data = load_config(path)
    explicit_command = next((arg for arg in remaining if arg in COMMANDS), None)
    command = explicit_command or data["command"]
    if explicit_command:
        remaining.remove(explicit_command)
    common = data.get("common", {})
    parameters = data.get("parameters", {})
    if not isinstance(common, dict) or not isinstance(parameters, dict):
        raise ValueError("'common' ve 'parameters' JSON nesnesi olmali")
    return [command, *_option_args(common), *_option_args(parameters), *remaining]
