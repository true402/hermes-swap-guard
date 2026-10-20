"""Parity with the OpenClaw guard: every case below was answered by its TypeScript detectTrade
(tests/detect_cases.json is generated from it), and this port must give exactly the same answer."""
import json
from pathlib import Path

import pytest

from true402_swap_guard.detect import detect_trade

CASES = json.loads((Path(__file__).parent / "detect_cases.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=[f"{c['tool']}:{json.dumps(c['params'])[:60]}" for c in CASES])
def test_same_answer_as_the_typescript_guard(case):
    got = [{"chain": t.chain, "token": t.token, "maybeSold": t.maybe_sold} for t in detect_trade(case["tool"], case["params"], case["defaultChain"])]
    assert got == case["expected"]


def test_the_cases_cover_buys_skips_and_evasions():
    assert len(CASES) >= 50
    assert any(c["expected"] == [] for c in CASES)
    assert any(any(t["maybeSold"] for t in c["expected"]) for c in CASES)
    assert any(any(t["chain"] == "unsupported" for t in c["expected"]) for c in CASES)
    assert any(any(t["chain"] == "solana" for t in c["expected"]) for c in CASES)
