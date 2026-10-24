"""Ask true402 about one token and reduce the answer to a Verdict — FREE checks only.

The catalog edition of the swap guard: it never pays and holds no wallet key. Each check is one plain
HTTP request served by true402's small daily free allowance; when that is used up the token counts as
"could not be checked" (which the guard lets through by default, with a warning). For paid checks,
install the full edition from the repository (subdirectory true402_swap_guard).
"""
from __future__ import annotations

from typing import Callable

import requests

from ._client import CLIENT_ID, VERSION
from .detect import TradeTarget
from .guard import Verdict, clean

NOT_A_TOKEN = {"not_a_contract", "mint_unreadable", "mint_not_initialized"}
SOL_NEVER_SELLABLE = {"non_transferable", "permanent_delegate"}
SOL_SELL_BLOCKABLE = {"freeze_authority_active", "pausable", "transfer_hook", "default_frozen"}

BASE_URL = "https://true402.dev/api"
# One request, well inside Hermes' 30 s pre_tool_call limit (over it, the tool is blocked).
TIMEOUT_S = 10.0


def _strings(v) -> list:
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def evm_verdict(r: dict, chain: str) -> Verdict:
    flags = _strings((r.get("safety") or {}).get("flags"))
    if any(f in NOT_A_TOKEN for f in flags):
        return Verdict("unchecked", [f"no token contract at this address on {chain}"], not_token=True)
    verdict = r.get("verdict") or {}
    reasons = [clean(s) for s in _strings(verdict.get("reasons"))]
    level = {"avoid": "danger", "caution": "caution", "ok": "ok"}.get(verdict.get("rating"))
    return Verdict(level, reasons) if level else Verdict("unchecked", ["no verdict in the answer"])


def solana_verdict(r: dict) -> Verdict:
    flags = _strings(r.get("flags"))
    if any(f in NOT_A_TOKEN for f in flags):
        return Verdict("unchecked", ["not a token mint on solana"], not_token=True)
    reasons = [clean(f.replace("_", " ")) for f in flags]
    if any(f in SOL_NEVER_SELLABLE for f in flags):
        return Verdict("danger", reasons)
    can_stop = any(f in SOL_SELL_BLOCKABLE for f in flags)
    risk = r.get("risk")
    if risk == "critical":
        return Verdict("danger", reasons)
    if risk == "high":
        return Verdict("danger" if can_stop else "caution", reasons)
    if risk in ("medium", "low"):
        return Verdict("caution" if can_stop else "ok", reasons)
    return Verdict("unchecked", ["no risk level in the answer"])


def create_checker(base_url: str = BASE_URL) -> Callable[[TradeTarget], Verdict]:
    ua = f"true402-{CLIENT_ID}/{VERSION} (+https://true402.dev)"

    def check(t: TradeTarget) -> Verdict:
        path = "/v1/solana/token-safety" if t.chain == "solana" else f"/v1/{t.chain}/token-report"
        res = requests.post(base_url.rstrip("/") + path, json={"token": t.token}, headers={"user-agent": ua},
                            timeout=TIMEOUT_S, allow_redirects=False)
        if res.status_code == 402:
            raise RuntimeError("the free daily checks are used up")
        if not 200 <= res.status_code < 300:
            raise RuntimeError(f"true402 answered HTTP {res.status_code}")
        body = res.json()
        body = body if isinstance(body, dict) else {}
        return solana_verdict(body) if t.chain == "solana" else evm_verdict(body, t.chain)

    return check
