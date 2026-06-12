import pytest
import json

import bottleneck_hunter as bh
import bh_agent


def test_load_command_requires_authorized_target(monkeypatch):
    monkeypatch.setattr("sys.argv", ["bottleneck_hunter.py", "load", "--url", "https://example.com", "--no-save"])
    with pytest.raises(ValueError, match="authorized-target"):
        bh.main()


def test_parser_caps_stress_concurrency():
    parser = bh.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["stress", "--url", "https://example.com", "--max", "201"])


def test_main_runs_from_config_without_runtime_prompts(tmp_path, monkeypatch):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({
        "command": "latency",
        "common": {"no_save": True},
        "parameters": {"url": "https://example.com", "repeat": 3, "no_direct": True},
    }))
    called = {}
    monkeypatch.setattr("sys.argv", ["bottleneck_hunter.py", "--config", str(config)])
    monkeypatch.setattr(bh, "test_latency", lambda url, cfg, repeat, compare_direct: called.update(url=url, repeat=repeat, compare_direct=compare_direct) or {"test": "latency"})
    bh.main()
    assert called == {"url": "https://example.com", "repeat": 3, "compare_direct": False}


def test_agent_saves_final_report_with_ai_analysis(monkeypatch):
    result = {"test": "latency"}
    saved = []
    monkeypatch.setattr("sys.argv", ["bh_agent.py", "latency", "--prefix", "final"])
    main_argv = []
    monkeypatch.setattr(bh, "main", lambda: main_argv.extend(__import__("sys").argv) or result)
    monkeypatch.setattr(bh_agent, "yorumla", lambda value: "Darbogaz TLS fazinda.")
    monkeypatch.setattr(bh, "save_report", lambda value, prefix="bottleneck": saved.append((prefix, value.copy())))

    bh_agent.run()

    assert "--no-save" in main_argv
    assert saved[-1][0] == "final"
    assert saved[-1][1]["ai_analysis"] == "Darbogaz TLS fazinda."


def test_agent_still_saves_final_report_when_ai_analysis_fails(monkeypatch):
    result = {"test": "latency"}
    saved = []
    monkeypatch.setattr("sys.argv", ["bh_agent.py", "latency"])
    monkeypatch.setattr(bh, "main", lambda: result)
    monkeypatch.setattr(bh_agent, "yorumla", lambda value: (_ for _ in ()).throw(RuntimeError("offline")))
    monkeypatch.setattr(bh, "save_report", lambda value, prefix="bottleneck": saved.append(value.copy()))

    bh_agent.run()

    assert saved == [{"test": "latency"}]
