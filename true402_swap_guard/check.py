"""Ask true402 about one token and reduce the answer to a Verdict. Port of the OpenClaw guard's check.ts.

EVM tokens: POST /v1/{chain}/token-report -> verdict.rating avoid | caution | ok (an executed buy + sell
simulation, deployer history, recent liquidity pulls). Solana mints: POST /v1/solana/token-safety ->
risk + flags. Without a payer key the call is a plain request, served by true402's small daily free
allowance; with one, pay_stall pays the exact quoted price over x402 (USDC on Base) when needed.
"""
from __future__ import annotations

import json
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

import requests

from ._client import CLIENT_ID, VERSION
from .detect import TradeTarget
from .guard import Verdict, clean


def pay_stall(path, payload, opts):
    """The paid path only. Imported lazily: eth-account is needed to SIGN a payment, never for free
    checks, so a user who declines the dependency install still gets a working (free-only) guard."""
    from .x402 import pay_stall as _pay

    return _pay(path, payload, opts)

NOT_A_TOKEN = {"not_a_contract", "mint_unreadable", "mint_not_initialized"}
SOL_NEVER_SELLABLE = {"non_transferable", "permanent_delegate"}
SOL_SELL_BLOCKABLE = {"freeze_authority_active", "pausable", "transfer_hook", "default_frozen"}

# Default per-check ceiling and daily count: together never more than $1.00 a day.
DEFAULT_MAX_PER_CHECK_USD = 0.02
DEFAULT_MAX_PAID_CHECKS_PER_DAY = 50

# Deadlines sized to Hermes' 30 s pre_tool_call limit (a callback over it blocks the tool). Without a key:
# one free request, 10 s. With a key: free request 4 s, then only on a 402 pay_stall's 4 s probe + 4 s
# balance read + 13 s paid request = 25 s in all.
FREE_TIMEOUT_S = 10.0
FREE_FIRST_TIMEOUT_S = 4.0
PROBE_TIMEOUT_S = 4.0
PAID_TIMEOUT_S = 13.0


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
    # Can never be sold, or can be taken from you: danger whatever the score says.
    if any(f in SOL_NEVER_SELLABLE for f in flags):
        return Verdict("danger", reasons)
    # An issuer who can stop your sell blocks only when the overall risk is already high.
    can_stop = any(f in SOL_SELL_BLOCKABLE for f in flags)
    risk = r.get("risk")
    if risk == "critical":
        return Verdict("danger", reasons)
    if risk == "high":
        return Verdict("danger" if can_stop else "caution", reasons)
    if risk in ("medium", "low"):
        return Verdict("caution" if can_stop else "ok", reasons)
    return Verdict("unchecked", ["no risk level in the answer"])


class FileSpendStore:
    """The day's paid-check count, kept OUTSIDE the process so a restart does not reset the limit.

    `locked()` serialises read-compare-write across threads (checks run in parallel) AND processes
    (several Hermes sessions may share one data directory, via an OS file lock); writes are atomic
    (temp file + os.replace), so a crash mid-write cannot reset the count.
    """

    _thread_lock = threading.Lock()

    def __init__(self, path: Path):
        self.path = path

    @contextmanager
    def locked(self):
        with self._thread_lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path.with_suffix(".lock"), "a") as fh:
                try:
                    import fcntl

                    fcntl.flock(fh, fcntl.LOCK_EX)
                except ImportError:  # Windows: the thread lock still covers this process
                    pass
                yield

    def read(self) -> dict:
        try:
            v = json.loads(self.path.read_text())
            return {"day": v.get("day", "") if isinstance(v.get("day"), str) else "",
                    "count": v["count"] if isinstance(v.get("count"), int) and v["count"] >= 0 else 0}
        except Exception:  # noqa: BLE001 — unreadable = a fresh day
            return {"day": "", "count": 0}

    def write(self, v: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
        tmp.write_text(json.dumps(v))
        tmp.chmod(0o600)
        os.replace(tmp, self.path)


class MemorySpendStore:
    def __init__(self):
        self.v = {"day": "", "count": 0}
        self._lock = threading.Lock()

    @contextmanager
    def locked(self):
        with self._lock:
            yield

    def read(self) -> dict:
        return self.v

    def write(self, v: dict) -> None:
        self.v = v


class LimitReached(RuntimeError):
    pass


@dataclass
class CheckConfig:
    payer_private_key: Optional[str] = None
    base_url: str = "https://true402.dev/api"
    max_amount_usd: float = DEFAULT_MAX_PER_CHECK_USD
    max_paid_checks_per_day: int = DEFAULT_MAX_PAID_CHECKS_PER_DAY


def create_checker(cfg: CheckConfig, store, now: Callable[[], float] = time.time) -> Callable[[TradeTarget], Verdict]:
    ua = f"true402-{CLIENT_ID}/{VERSION} (+https://true402.dev)"

    def to_verdict(t: TradeTarget, body) -> Verdict:
        body = body if isinstance(body, dict) else {}
        return solana_verdict(body) if t.chain == "solana" else evm_verdict(body, t.chain)

    def free(path: str, token: str, timeout: float):
        """The free request. Returns None on a 402 (payment needed)."""
        res = requests.post(cfg.base_url.rstrip("/") + path, json={"token": token},
                            headers={"user-agent": ua}, timeout=timeout, allow_redirects=False)
        if res.status_code == 402:
            return None
        if not 200 <= res.status_code < 300:
            raise RuntimeError(f"true402 answered HTTP {res.status_code}")
        return res.json()

    def check(t: TradeTarget) -> Verdict:
        path = "/v1/solana/token-safety" if t.chain == "solana" else f"/v1/{t.chain}/token-report"
        body = free(path, t.token, FREE_FIRST_TIMEOUT_S if cfg.payer_private_key else FREE_TIMEOUT_S)
        if body is not None:
            return to_verdict(t, body)
        if not cfg.payer_private_key:
            raise RuntimeError("the free daily checks are used up - set TRUE402_PAYER_PRIVATE_KEY to pay per check")

        # An OVERALL spending limit, counted per UTC day in a file BEFORE paying (a failed payment still
        # counts), so a restart does not reset it. If the count cannot be saved, no payment is made.
        today = time.strftime("%Y-%m-%d", time.gmtime(now()))
        try:
            # Read, compare and write under one lock: parallel checks must not both see the last slot.
            with store.locked():
                saved = store.read()
                paid_today = saved["count"] if saved["day"] == today else 0
                if paid_today >= cfg.max_paid_checks_per_day:
                    raise LimitReached(f"the daily limit of {cfg.max_paid_checks_per_day} paid checks is reached (max_paid_checks_per_day)")
                store.write({"day": today, "count": paid_today + 1})
        except LimitReached:
            raise
        except Exception as e:  # noqa: BLE001
            raise RuntimeError("could not record the paid-check count, so no payment was made") from e
        from .x402 import PayOpts

        opts = PayOpts(payer_private_key=cfg.payer_private_key, base_url=cfg.base_url, max_amount_usd=cfg.max_amount_usd,
                       timeout=PROBE_TIMEOUT_S, paid_timeout=PAID_TIMEOUT_S)
        return to_verdict(t, pay_stall(path, {"token": t.token}, opts))

    return check
