import pytest

import bottleneck_hunter as bh


def test_load_command_requires_authorized_target(monkeypatch):
    monkeypatch.setattr("sys.argv", ["bottleneck_hunter.py", "load", "--url", "https://example.com", "--no-save"])
    with pytest.raises(ValueError, match="authorized-target"):
        bh.main()


def test_parser_caps_stress_concurrency():
    parser = bh.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["stress", "--url", "https://example.com", "--max", "201"])
