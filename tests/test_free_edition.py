"""The catalog build: free checks only. It must hold no payment path at all (Hermes catalog rule for
services with no public operator, PR #142252), and its detection/decision code must stay the SAME code
as the full edition's."""
import ast
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FREE = ROOT / "true402_swap_guard_free"
FULL = ROOT / "true402_swap_guard"


@pytest.mark.parametrize("name", ["detect.py", "guard.py"])
def test_shared_logic_is_byte_identical_to_the_full_edition(name):
    assert (FREE / name).read_bytes() == (FULL / name).read_bytes(), f"copy {FULL / name} to {FREE / name}"


def test_no_payment_code_anywhere_in_the_free_edition():
    names = {p.name for p in FREE.glob("*.py")}
    assert "x402.py" not in names
    for p in FREE.glob("*.py"):
        tree = ast.parse(p.read_text())
        imported = {(n.module or "") for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)} | {
            a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        assert not imported & {"eth_account", ".x402", "x402", "agent.secret_scope", "agent"}, p.name
        assert "get_secret" not in p.read_text() and "PRIVATE_KEY" not in p.read_text(), p.name
    manifest = (FREE / "plugin.yaml").read_text()
    assert "eth-account" not in manifest and "secret" not in manifest and "requires_env" not in manifest


class Resp:
    def __init__(self, status, body=None):
        self.status_code, self._b = status, body if body is not None else {}

    def json(self):
        return self._b


def test_free_checker_never_pays(monkeypatch):
    from true402_swap_guard_free import check as chk
    from true402_swap_guard_free.detect import TradeTarget
    seen = {}
    def post(url, json, headers, timeout, allow_redirects):
        seen.update(url=url, ua=headers["user-agent"])
        return Resp(200, {"verdict": {"rating": "avoid", "reasons": ["rug"]}})
    monkeypatch.setattr(chk.requests, "post", post)
    assert chk.create_checker()(TradeTarget("bsc", "0x" + "1" * 40)).level == "danger"
    assert seen["url"].endswith("/v1/bsc/token-report") and seen["ua"].startswith("true402-hermes-guard-free/")
    monkeypatch.setattr(chk.requests, "post", lambda *a, **k: Resp(402))
    with pytest.raises(RuntimeError, match="free daily checks are used up"):
        chk.create_checker()(TradeTarget("base", "0x" + "1" * 40))


def test_registers_the_hook_and_reads_no_secret(monkeypatch):
    import true402_swap_guard_free as plugin
    monkeypatch.setitem(sys.modules, "agent", types.ModuleType("agent"))  # any secret read would fail loudly
    hooks = {}
    class Ctx:
        def get_config(self, key, default=None):
            return {"on_unchecked": "block"}.get(key, default)
        def register_hook(self, name, fn):
            hooks[name] = fn
    plugin.register(Ctx())
    assert set(hooks) == {"pre_tool_call"}
    assert hooks["pre_tool_call"](tool_name="read_file", args={"path": "/x"}) is None
