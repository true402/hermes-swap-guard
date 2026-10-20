"""Turn true402 verdicts into a Hermes pre_tool_call directive. Port of the OpenClaw guard's guard.ts.

A trade is BLOCKED only on a definite danger verdict for a token being bought. Anything that could not
be checked lets the trade through by default (on_unchecked), because a guard that breaks every swap when
a third party hiccups gets uninstalled. The STRICTEST outcome across every token wins: block > ask > allow.
"""
from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Callable, Optional

from .detect import UNSUPPORTED, TradeTarget, detect_trade

MAX_TOKENS = 5
# Hermes fails a pre_tool_call callback CLOSED (blocks the tool) after plugins.hook_callback_timeout,
# 30 s by default. Every check in one call runs in parallel and must finish inside this budget.
CALL_BUDGET_S = 26.0


@dataclass
class Verdict:
    level: str  # danger | caution | ok | unchecked
    reasons: list = field(default_factory=list)
    not_token: bool = False  # unchecked only because there is no token at this address on that chain


Checker = Callable[[TradeTarget], Verdict]


@dataclass
class GuardConfig:
    default_chain: str = "base"
    on_caution: str = "allow"  # allow | ask
    on_unchecked: str = "allow"  # allow | ask | block
    allow_tokens: list = field(default_factory=list)
    cache_s: float = 600.0


def clean(s: str, limit: int = 160) -> str:
    """Server and error text goes in front of a model and a user: no control characters, bounded."""
    t = re.sub(r"[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]", " ", str(s))
    t = re.sub(r"\s+", " ", t).strip()
    return t if len(t) <= limit else t[: limit - 1] + "…"


def _reasons(v: Verdict) -> str:
    return f" ({'; '.join(v.reasons[:4])})" if v.reasons else ""


class Guard:
    def __init__(self, check: Checker, cfg: GuardConfig, warn: Callable[[str], None] = lambda m: None,
                 now: Callable[[], float] = time.time):
        self.check, self.cfg, self.warn, self.now = check, cfg, warn, now
        self.allow = {a.lower() for a in cfg.allow_tokens}
        self.cache: dict = {}
        self.warned: dict = {}
        self.pool = ThreadPoolExecutor(max_workers=MAX_TOKENS * 4, thread_name_prefix="true402-guard")

    def _warn_once(self, why: str) -> None:
        last = self.warned.get(why)
        if last is not None and self.now() - last < 600:
            return
        self.warned[why] = self.now()
        outcome = {"block": "blocked", "ask": "held for approval"}.get(self.cfg.on_unchecked, "allowed unchecked")
        self.warn(f"true402 swap guard: a token could not be checked ({why}); the trade was {outcome}.")

    def _verdict(self, t: TradeTarget) -> Verdict:
        key = f"{t.chain}:{t.token.lower()}"
        hit = self.cache.get(key)
        if hit and self.now() - hit[0] < self.cfg.cache_s:
            return hit[1]
        try:
            v = self.check(t)
        except Exception as e:  # noqa: BLE001 — any failure is "could not check", never a crash
            v = Verdict("unchecked", [clean(str(e))])
        if v.level != "unchecked":  # never cache "unchecked": the next call may get through
            self.cache[key] = (self.now(), v)
        return v

    def __call__(self, tool_name: str, args: dict) -> Optional[dict]:
        targets = [t for t in detect_trade(tool_name, args or {}, self.cfg.default_chain) if t.token.lower() not in self.allow]
        if not targets:
            return None

        # One token may be listed on several chains (the default chain is always among them); results
        # combine PER TOKEN. The cap counts distinct tokens; more than that is never waved through.
        groups: dict = {}
        for t in targets:
            groups.setdefault(t.token.lower(), []).append(t)
        if len(groups) > MAX_TOKENS:
            why = f"this call names {len(groups)} tokens; the guard checks at most {MAX_TOKENS} per call"
            self._warn_once(why)
            if self.cfg.on_unchecked == "block":
                return {"action": "block", "message": f"true402 swap guard blocked this trade: {why}."}
            return {"action": "approve", "message": f"Too many tokens to check: {why}.", "rule_key": "true402-swap-guard:too-many"}

        futures = {}
        for ts in groups.values():
            for t in ts:
                if t.chain != UNSUPPORTED:
                    futures[(t.chain, t.token.lower())] = self.pool.submit(self._verdict, t)
        wait(list(futures.values()), timeout=CALL_BUDGET_S)

        def got(t: TradeTarget) -> Verdict:
            if t.chain == UNSUPPORTED:
                return Verdict("unchecked", ["a chain true402 does not serve"])
            f = futures[(t.chain, t.token.lower())]
            return f.result() if f.done() else Verdict("unchecked", [f"no answer within {CALL_BUDGET_S:.0f} s"])

        results = []
        for ts in groups.values():
            vs = [got(t) for t in ts]
            pick = next((i for i, v in enumerate(vs) if v.level == "danger"), None)
            if pick is None:
                # A chain we do not serve: a clean verdict on ANOTHER chain says nothing. Only danger counts.
                pick = next((i for i, t in enumerate(ts) if t.chain == UNSUPPORTED), None)
            if pick is None:
                # Only "no token at this address on that chain" may be set aside for another chain's verdict.
                pick = next((i for i, v in enumerate(vs) if v.level == "unchecked" and not v.not_token), None)
            if pick is None:
                pick = next((i for lvl in ("caution", "ok") for i, v in enumerate(vs) if v.level == lvl), None)
            if pick is None:
                results.append((ts[0], Verdict("unchecked", list(dict.fromkeys(r for v in vs for r in v.reasons)))))
            else:
                results.append((ts[pick], vs[pick]))

        danger = next(((t, v) for t, v in results if v.level == "danger" and not t.maybe_sold), None)
        if danger:
            t, v = danger
            return {"action": "block", "message": (
                f"true402 swap guard blocked this trade: {t.token} on {t.chain} was rated dangerous{_reasons(v)}. "
                "Do not retry it with another tool. To trade it anyway, add the address to the plugin's "
                "allow_tokens setting.")}

        unchecked = next(((t, v) for t, v in results if v.level == "unchecked"), None)
        unchecked_why = None
        if unchecked:
            t, v = unchecked
            self._warn_once(v.reasons[0] if v.reasons else "unknown")
            unchecked_why = f"true402 could not check {t.token} on {t.chain}{_reasons(v)}."
            if self.cfg.on_unchecked == "block":
                return {"action": "block", "message": f"true402 swap guard blocked this trade: {unchecked_why}"}

        asks = []
        sold = next(((t, v) for t, v in results if v.level == "danger" and t.maybe_sold), None)
        if sold:
            t, v = sold
            asks.append(f"true402 rated {t.token} on {t.chain} dangerous{_reasons(v)}. If you are selling it, approve; if this buys it, deny.")
        caution = next(((t, v) for t, v in results if v.level == "caution"), None)
        if caution and self.cfg.on_caution == "ask":
            t, v = caution
            asks.append(f"true402 rated {t.token} on {t.chain} \"caution\"{_reasons(v)}.")
        if unchecked_why and self.cfg.on_unchecked == "ask":
            asks.append(unchecked_why)
        if asks:
            # Hermes' approval gate: denial, timeout or an unattended run (cron, gateway) fails closed.
            return {"action": "approve", "message": " ".join(asks), "rule_key": "true402-swap-guard"}
        return None
