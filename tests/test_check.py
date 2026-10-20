import pytest

from true402_swap_guard import check as chk
from true402_swap_guard.check import CheckConfig, FileSpendStore, MemorySpendStore, create_checker, evm_verdict, solana_verdict
from true402_swap_guard.detect import TradeTarget

ADDR = "0x1111111111111111111111111111111111111111"
KEY = "0x" + "11" * 32


class Resp:
    def __init__(self, status, body=None):
        self.status_code, self._b = status, body or {}

    def json(self):
        return self._b


def test_evm_verdict_maps_ratings_and_treats_a_non_contract_as_unchecked():
    assert evm_verdict({"verdict": {"rating": "avoid", "reasons": ["honeypot"]}}, "base").level == "danger"
    assert evm_verdict({"verdict": {"rating": "caution"}}, "base").level == "caution"
    assert evm_verdict({"verdict": {"rating": "ok"}}, "base").level == "ok"
    v = evm_verdict({"verdict": {"rating": "avoid"}, "safety": {"flags": ["not_a_contract"]}}, "base")
    assert v.level == "unchecked" and v.not_token
    assert evm_verdict({}, "base").level == "unchecked"


def test_solana_verdict_rules():
    assert solana_verdict({"risk": "critical", "flags": []}).level == "danger"
    assert solana_verdict({"risk": "medium", "flags": ["non_transferable"]}).level == "danger"
    assert solana_verdict({"risk": "high", "flags": ["freeze_authority_active"]}).level == "danger"
    assert solana_verdict({"risk": "medium", "flags": ["freeze_authority_active"]}).level == "caution"
    assert solana_verdict({"risk": "high", "flags": ["low_liquidity"]}).level == "caution"
    assert solana_verdict({"risk": "low", "flags": []}).level == "ok"
    assert solana_verdict({"risk": "critical", "flags": ["mint_unreadable"]}).not_token


def test_free_check_path_ua_and_402(monkeypatch):
    seen = {}
    def post(url, json, headers, timeout, allow_redirects):
        seen.update(url=url, ua=headers["user-agent"], body=json, timeout=timeout)
        return Resp(200, {"verdict": {"rating": "avoid", "reasons": ["rug"]}})
    monkeypatch.setattr(chk.requests, "post", post)
    v = create_checker(CheckConfig(), MemorySpendStore())(TradeTarget("ethereum", ADDR))
    assert v.level == "danger" and seen["url"] == "https://true402.dev/api/v1/ethereum/token-report"
    assert seen["ua"].startswith("true402-hermes-guard/") and seen["body"] == {"token": ADDR}
    monkeypatch.setattr(chk.requests, "post", lambda *a, **k: Resp(402))
    with pytest.raises(RuntimeError, match="TRUE402_PAYER_PRIVATE_KEY"):
        create_checker(CheckConfig(), MemorySpendStore())(TradeTarget("base", ADDR))


def test_with_a_key_a_free_answer_spends_nothing(monkeypatch):
    monkeypatch.setattr(chk.requests, "post", lambda *a, **k: Resp(200, {"verdict": {"rating": "ok"}}))
    monkeypatch.setattr(chk, "pay_stall", lambda *a, **k: pytest.fail("must not pay when the free check answered"))
    store = MemorySpendStore()
    assert create_checker(CheckConfig(payer_private_key=KEY), store)(TradeTarget("base", ADDR)).level == "ok"
    assert store.read()["count"] == 0


def test_daily_paid_limit_survives_a_restart_and_resets_next_day(monkeypatch, tmp_path):
    monkeypatch.setattr(chk.requests, "post", lambda *a, **k: Resp(402))
    paid = []
    monkeypatch.setattr(chk, "pay_stall", lambda path, payload, opts: paid.append(opts) or {"verdict": {"rating": "ok"}})
    t = [1792440000.0]  # 2026-10-20
    cfg = CheckConfig(payer_private_key=KEY, max_paid_checks_per_day=1)
    first = create_checker(cfg, FileSpendStore(tmp_path / "spend.json"), now=lambda: t[0])
    assert first(TradeTarget("base", ADDR)).level == "ok"
    restarted = create_checker(cfg, FileSpendStore(tmp_path / "spend.json"), now=lambda: t[0])
    with pytest.raises(RuntimeError, match="daily limit of 1 paid checks"):
        restarted(TradeTarget("base", ADDR))
    t[0] += 86400
    assert restarted(TradeTarget("base", ADDR)).level == "ok"
    assert len(paid) == 2 and paid[0].max_amount_usd == 0.02
    assert paid[0].timeout + paid[0].timeout + paid[0].paid_timeout + chk.FREE_FIRST_TIMEOUT_S <= 25


def test_no_payment_when_the_count_cannot_be_saved(monkeypatch):
    monkeypatch.setattr(chk.requests, "post", lambda *a, **k: Resp(402))
    monkeypatch.setattr(chk, "pay_stall", lambda *a, **k: pytest.fail("must not pay"))
    class Broken(MemorySpendStore):
        def read(self):
            return {"day": "", "count": 0}
        def write(self, v):
            raise OSError("read-only disk")
    with pytest.raises(RuntimeError, match="no payment was made"):
        create_checker(CheckConfig(payer_private_key=KEY), Broken())(TradeTarget("base", ADDR))


def test_parallel_paid_checks_never_exceed_the_daily_limit(monkeypatch, tmp_path):
    """Checks run in parallel threads: the read-compare-write must be atomic (commit review, 2026-10-20)."""
    import threading
    monkeypatch.setattr(chk.requests, "post", lambda *a, **k: Resp(402))
    paid = []
    lock = threading.Lock()
    def pay(path, payload, opts):
        with lock:
            paid.append(1)
        return {"verdict": {"rating": "ok"}}
    monkeypatch.setattr(chk, "pay_stall", pay)
    # A store whose read is slow, so unsynchronised threads WOULD all read the same count.
    class Slow(FileSpendStore):
        def read(self):
            v = super().read()
            import time as _t; _t.sleep(0.01)
            return v
    check = create_checker(CheckConfig(payer_private_key=KEY, max_paid_checks_per_day=3), Slow(tmp_path / "spend.json"))
    errors = []
    def run():
        try:
            check(TradeTarget("base", ADDR))
        except RuntimeError as e:
            errors.append(str(e))
    threads = [threading.Thread(target=run) for _ in range(10)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert len(paid) == 3 and len(errors) == 7
    assert all("daily limit" in e for e in errors)
