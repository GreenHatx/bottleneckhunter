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


def test_full_reuses_per_test_configuration(monkeypatch):
    calls = []
    monkeypatch.setattr(bh, "test_latency", lambda url, cfg, repeat, compare_direct: calls.append(("latency", url, repeat)) or {})
    monkeypatch.setattr(bh, "test_ssl", lambda url, bypass, cfg, repeat: calls.append(("ssl", url, bypass, repeat)) or {})
    monkeypatch.setattr(bh, "test_load", lambda url, cfg, levels, requests_per_level: calls.append(("load", url, levels, requests_per_level)) or {})
    monkeypatch.setattr(bh, "test_cache", lambda url, cfg, rounds: calls.append(("cache", url, rounds)) or {})
    monkeypatch.setattr(bh, "test_browser", lambda *args, **kwargs: {})
    monkeypatch.setattr(bh, "test_soak", lambda *args, **kwargs: {})
    monkeypatch.setattr(bh, "test_stress", lambda *args, **kwargs: {})
    args = type("Args", (), {
        "url": "legacy", "repeat": 1, "bypass_url": None, "levels": (1,), "requests": 1,
        "cache_rounds": 1, "throughput_url": None, "browser": False, "soak": 0, "soak_interval": 5,
    })()

    bh.test_full(args, bh.ProxyConfig(), tests={
        "latency": {"url": "latency", "repeat": 2},
        "ssl": {"url": "inspected", "bypass_url": "bypass", "repeat": 3},
        "load": {"url": "load", "levels": "2,3", "requests": 4},
        "cache": {"url": "cache", "rounds": 5},
    })

    assert calls == [
        ("latency", "latency", 2), ("ssl", "inspected", "bypass", 3),
        ("load", "load", (2, 3), 4), ("cache", "cache", 5),
    ]


def test_full_always_runs_browser_soak_and_stress(monkeypatch):
    calls = []
    monkeypatch.setattr(bh, "test_latency", lambda *args, **kwargs: {})
    monkeypatch.setattr(bh, "test_load", lambda *args, **kwargs: {})
    monkeypatch.setattr(bh, "test_cache", lambda *args, **kwargs: {})
    monkeypatch.setattr(bh, "test_browser", lambda url, cfg, **kwargs: calls.append(("browser", url, kwargs)) or {})
    monkeypatch.setattr(bh, "test_soak", lambda url, cfg, **kwargs: calls.append(("soak", url, kwargs)) or {})
    monkeypatch.setattr(bh, "test_stress", lambda url, cfg, **kwargs: calls.append(("stress", url, kwargs)) or {})
    args = type("Args", (), {
        "url": "legacy", "repeat": 1, "bypass_url": None, "levels": (1,), "requests": 1,
        "cache_rounds": 1, "throughput_url": None, "browser": False, "soak": 0, "soak_interval": 5,
    })()

    result = bh.test_full(args, bh.ProxyConfig(), tests={
        "browser": {"enabled": False, "url": "browser", "repeat": 2},
        "soak": {"url": "soak", "duration": 3, "interval": 1, "concurrency": 2},
        "stress": {"enabled": False, "url": "stress", "max": 20, "no_proxy_mode": True},
    })

    assert set(result["components"]) >= {"browser", "soak", "stress"}
    assert [call[0] for call in calls] == ["browser", "soak", "stress"]
    assert calls[-1][2]["max_conc"] == 20
    assert calls[-1][2]["via_proxy"] is False


def test_full_accepts_load_section_authorization(tmp_path, monkeypatch):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({
        "command": "full",
        "common": {"no_save": True, "authorized_target": False},
        "tests": {
            "full": {"url": "https://target"},
            "load": {"url": "https://target", "levels": "1", "requests": 1, "authorized_target": True},
        },
    }))
    monkeypatch.setattr("sys.argv", ["bottleneck_hunter.py", "--config", str(config)])
    monkeypatch.setattr(bh, "test_full", lambda *args, **kwargs: {"test": "full"})

    bh.main()
