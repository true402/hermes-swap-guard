"""true402 swap guard for Hermes — FREE edition (the catalog build).

Before any tool call that BUYS a token, check the token with true402 (an executed buy + sell simulation
on Base / Ethereum / BSC, mint authorities on Solana) and block the call when the token is a honeypot
or a rug in progress. One pre_tool_call hook covers every trading tool, MCP server and terminal command.

This edition never pays and holds no wallet key: it uses true402's small daily free allowance, and a
token it cannot check passes by default (with a warning). Paid checks live in the full edition, in the
same repository (subdirectory true402_swap_guard).
"""
from __future__ import annotations

import logging

from .check import create_checker
from .guard import Guard, GuardConfig

PLUGIN = "true402-swap-guard"
SETTINGS = ("default_chain", "on_caution", "on_unchecked", "allow_tokens")
log = logging.getLogger(PLUGIN)


def read_config(raw) -> GuardConfig:
    c = raw if isinstance(raw, dict) else {}

    def pick(v, allowed, default):
        return v if v in allowed else default

    return GuardConfig(
        default_chain=pick(c.get("default_chain"), ("base", "ethereum", "bsc"), "base"),
        on_caution=pick(c.get("on_caution"), ("allow", "ask"), "allow"),
        on_unchecked=pick(c.get("on_unchecked"), ("allow", "ask", "block"), "allow"),
        allow_tokens=[x for x in c.get("allow_tokens", []) if isinstance(x, str)] if isinstance(c.get("allow_tokens"), list) else [],
    )


def register(ctx):
    # ctx.get_config(key, default) reads ONE setting under plugins.entries.<id>.settings.
    cfg = read_config({k: ctx.get_config(k, None) for k in SETTINGS})
    guard = Guard(create_checker(), cfg, warn=log.warning)

    def pre_tool_call(tool_name, args, task_id="", **kwargs):
        return guard(tool_name, args if isinstance(args, dict) else {})

    ctx.register_hook("pre_tool_call", pre_tool_call)
