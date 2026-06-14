import json

import bottleneck_hunter as bh


def test_interactive_uses_non_empty_config_values_without_prompting(tmp_path, monkeypatch):
    config = tmp_path / "bottleneck.config.json"
    config.write_text(json.dumps({
        "command": "latency",
        "common": {
            "proxy": "http://proxy:8080", "proxy_user": "user:pass",
            "insecure": False, "ssl_no_revoke": True, "timeout": 12, "no_save": True,
        },
        "parameters": {"url": "https://target", "repeat": 3, "no_direct": True},
    }))
    answers = iter(["1", "0"])
    prompts = []
    called = {}
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(bh, "prompt", lambda text, default=None: prompts.append(text) or next(answers))
    monkeypatch.setattr(bh, "test_latency", lambda url, cfg, repeat, compare_direct: called.update(
        url=url, proxy=cfg.proxy, timeout=cfg.timeout, repeat=repeat, compare_direct=compare_direct
    ) or {"test": "latency"})

    bh.interactive()

    assert called == {"url": "https://target", "proxy": "http://proxy:8080", "timeout": 12, "repeat": 3, "compare_direct": False}
    assert not any("Hedef URL" in text or "Proxy (" in text or "Timeout" in text or "Tekrar" in text for text in prompts)


def test_interactive_loops_and_displays_config(tmp_path, monkeypatch, capsys):
    config = tmp_path / "bottleneck.config.json"
    config.write_text(json.dumps({"command": "latency", "common": {}, "parameters": {"url": "https://target"}}))
    answers = iter(["11", "11", "0"])
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(bh, "prompt", lambda text, default=None: next(answers))

    bh.interactive()

    assert capsys.readouterr().out.count('"url": "https://target"') == 2


def test_display_config_masks_proxy_credentials(capsys):
    bh._display_config({"common": {"proxy_user": "admin:secret"}})

    output = capsys.readouterr().out
    assert "admin:secret" not in output
    assert '"proxy_user": "***"' in output


def test_interactive_ai_check_calls_callback(monkeypatch):
    answers = iter(["10", "0"])
    checks = []
    monkeypatch.setattr(bh, "prompt", lambda text, default=None: next(answers))

    bh.interactive(ai_check=lambda: checks.append(True))

    assert checks == [True]


def test_interactive_rejects_unauthorized_load_and_returns_to_menu(tmp_path, monkeypatch, capsys):
    config = tmp_path / "bottleneck.config.json"
    config.write_text(json.dumps({
        "command": "load",
        "common": {
            "proxy": "http://proxy:8080", "proxy_user": "user:pass", "insecure": False,
            "ssl_no_revoke": False, "timeout": 10, "no_save": True, "authorized_target": False,
        },
        "parameters": {"url": "https://target", "repeat": 1, "levels": "2", "requests": 2},
    }))
    answers = iter(["3", "0"])
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(bh, "prompt", lambda text, default=None: next(answers))
    monkeypatch.setattr(bh, "test_load", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not run")))

    bh.interactive()

    assert "Yuk testi baslatilmadi" in capsys.readouterr().out


def test_test_specific_authorization_overrides_common_false():
    config = {
        "common": {"authorized_target": False},
        "tests": {"load": {"authorized_target": True}},
    }

    assert bh._authorized(config, "load") is True
    assert bh._authorized(config, "stress") is False
