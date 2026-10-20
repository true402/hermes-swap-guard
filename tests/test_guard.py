import pytest

from true402_swap_guard.guard import Guard, GuardConfig, Verdict, clean

ADDR = "0x1111111111111111111111111111111111111111"
SCAM = "0x5555555555555555555555555555555555555555"
OTHER = "0x6666666666666666666666666666666666666666"
USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
BUY = {"command": f"npx awal@latest trade 1 usdc {ADDR}"}


def guard(check, **cfg):
    return Guard(check, GuardConfig(**cfg))


def const(level, *reasons, not_token=False):
    return lambda t: Verdict(level, list(reasons), not_token)


def test_blocks_a_dangerous_buy_with_reasons():
    r = guard(const("danger", "cannot be sold (honeypot)"))("terminal", BUY)
    assert r["action"] == "block" and "cannot be sold (honeypot)" in r["message"] and ADDR in r["message"]


def test_ok_and_caution_pass_by_default_caution_asks_when_configured():
    assert guard(const("ok"))("terminal", BUY) is None
    assert guard(const("caution", "young"))("terminal", BUY) is None
    r = guard(const("caution", "young"), on_caution="ask")("terminal", BUY)
    assert r["action"] == "approve" and "young" in r["message"]


def test_a_failed_check_never_blocks_unless_told_to():
    def down(t):
        raise RuntimeError("fetch failed")
    assert guard(down)("terminal", BUY) is None
    assert guard(down, on_unchecked="ask")("terminal", BUY)["action"] == "approve"
    assert guard(down, on_unchecked="block")("terminal", BUY)["action"] == "block"


def test_non_trades_majors_and_allow_listed_tokens_are_not_checked():
    calls = []
    g = guard(lambda t: calls.append(t) or Verdict("danger"), allow_tokens=[ADDR.upper().replace("0X", "0x")])
    assert g("terminal", {"command": "ls"}) is None
    assert g("terminal", BUY) is None
    assert calls == []


def test_verdicts_are_cached_but_unchecked_never_is():
    t = [0.0]
    calls = []
    g = Guard(lambda x: calls.append(x) or Verdict("ok"), GuardConfig(), now=lambda: t[0])
    g("terminal", BUY); g("terminal", BUY)
    assert len(calls) == 1
    t[0] = 700
    g("terminal", BUY)
    assert len(calls) == 2
    seq = iter([RuntimeError("timeout"), Verdict("danger")])
    def flaky(x):
        v = next(seq)
        if isinstance(v, Exception):
            raise v
        return v
    g2 = guard(flaky)
    assert g2("terminal", BUY) is None
    assert g2("terminal", BUY)["action"] == "block"


def test_too_many_tokens_are_never_waved_through():
    many = " ".join(f"0x{str(i) * 40}"[:42] for i in range(1, 8))
    calls = []
    g = guard(lambda t: calls.append(t) or Verdict("ok"))
    assert g("terminal", {"command": f"bot buy {many}"})["action"] == "approve"
    assert guard(const("ok"), on_unchecked="block")("terminal", {"command": f"bot buy {many}"})["action"] == "block"
    assert calls == []


def test_per_token_combination_across_chains():
    # "not a token on base" is set aside for bsc's real verdict...
    def per_chain(t):
        return Verdict("ok") if t.chain == "bsc" else Verdict("unchecked", ["no token contract"], not_token=True)
    assert guard(per_chain, on_unchecked="block")("terminal", {"command": f"bot buy {ADDR} --chain bsc"}) is None
    # ...but a FAILED check on the named chain is never replaced by a clean result elsewhere.
    def bsc_down(t):
        if t.chain == "bsc":
            raise RuntimeError("fetch failed")
        return Verdict("ok")
    assert guard(bsc_down, on_unchecked="block")("terminal", {"command": f"bot buy {ADDR} --chain bsc"})["action"] == "block"


def test_a_possibly_sold_dangerous_token_asks_a_clear_buy_blocks():
    g = guard(const("danger", "liquidity pulled"))
    sell = g("terminal", {"command": f'bot swap --token-in {ADDR} --token-out {USDC} "'})
    assert sell["action"] == "approve" and "If you are selling it" in sell["message"]
    assert g("terminal", BUY)["action"] == "block"


def test_strictest_outcome_wins():
    assert guard(const("danger", "honeypot"))("terminal", {"command": f"bot buy --token-out {SCAM} # --token-in {SCAM}"})["action"] == "block"
    def mixed(t):
        if t.token.lower() == OTHER:
            raise RuntimeError("fetch failed")
        return Verdict("danger", ["rug"])
    assert guard(mixed, on_unchecked="block")("terminal", {"command": f'bot swap --token-in {SCAM} "x {OTHER}'})["action"] == "block"


def test_unchecked_trades_warn_once_per_reason():
    warned = []
    t = [0.0]
    def down(x):
        raise RuntimeError("the free daily checks are used up")
    g = Guard(down, GuardConfig(), warn=warned.append, now=lambda: t[0])
    g("terminal", BUY); g("terminal", BUY)
    assert len(warned) == 1 and "allowed unchecked" in warned[0]
    t[0] = 700
    g("terminal", BUY)
    assert len(warned) == 2


def test_clean_strips_control_and_bidi_and_bounds_length():
    assert clean("a\x1b[31mb\u202ec\n d") == "a [31mb c d"
    assert len(clean("x" * 500)) == 160
