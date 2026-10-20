"""register(ctx) against a stand-in Hermes: the hook is wired, the key comes from get_secret only."""
import sys
import types

import true402_swap_guard as plugin


class Ctx:
    def __init__(self, config):
        self.config, self.hooks = config, {}

    def get_config(self, key, default=None):  # Hermes' real signature: one setting per call
        return self.config.get(key, default)

    def register_hook(self, name, fn):
        self.hooks[name] = fn


def fake_hermes(monkeypatch, tmp_path, secrets):
    agent = types.ModuleType("agent"); scope = types.ModuleType("agent.secret_scope")
    scope.get_secret = lambda name, default=None: secrets.get(name, default)
    plugins = types.ModuleType("plugins"); storage = types.ModuleType("plugins.plugin_storage")
    storage.plugin_data_dir = lambda name: tmp_path / name
    for n, m in {"agent": agent, "agent.secret_scope": scope, "plugins": plugins, "plugins.plugin_storage": storage}.items():
        monkeypatch.setitem(sys.modules, n, m)


def test_registers_pre_tool_call_and_reads_only_the_dedicated_key(monkeypatch, tmp_path):
    seen = {}
    fake_hermes(monkeypatch, tmp_path, {"TRUE402_PAYER_PRIVATE_KEY": "0xabc", "PAYER_PRIVATE_KEY": "0xother"})
    monkeypatch.setattr(plugin, "create_checker", lambda cfg, store: seen.update(key=cfg.payer_private_key, path=store.path) or (lambda t: None))
    ctx = Ctx({"on_unchecked": "block", "max_paid_checks_per_day": 3})
    plugin.register(ctx)
    assert set(ctx.hooks) == {"pre_tool_call"}
    assert seen["key"] == "0xabc" and seen["path"] == tmp_path / "true402-swap-guard" / "spend.json"
    assert ctx.hooks["pre_tool_call"](tool_name="read_file", args={"path": "/x"}, task_id="t") is None


def test_without_the_dedicated_key_only_free_checks_run(monkeypatch, tmp_path):
    seen = {}
    fake_hermes(monkeypatch, tmp_path, {"PAYER_PRIVATE_KEY": "0xother"})
    monkeypatch.setattr(plugin, "create_checker", lambda cfg, store: seen.update(key=cfg.payer_private_key) or (lambda t: None))
    plugin.register(Ctx({}))
    assert seen["key"] is None


def test_bad_settings_fall_back_to_safe_defaults():
    g, c = plugin.read_config({"on_unchecked": "yolo", "max_amount_usd": -1, "max_paid_checks_per_day": True, "default_chain": "arbitrum"})
    assert (g.on_unchecked, g.default_chain, c.max_amount_usd, c.max_paid_checks_per_day) == ("allow", "base", 0.02, 50)
