"""true402 swap guard for Hermes: before any tool call that BUYS a token, check the token with true402
(an executed buy + sell simulation on Base / Ethereum / BSC, mint authorities on Solana) and block the
call when the token is a honeypot or a rug in progress.

One pre_tool_call hook covers every trading tool, MCP server and terminal command the agent uses, so a
skill the agent forgets to follow cannot skip the check. Only DANGER blocks; anything that could not be
checked passes unless the user asks otherwise. Port of the OpenClaw plugin @true402.dev/openclaw-swap-guard.
"""
from __future__ import annotations

import logging

from .check import DEFAULT_MAX_PAID_CHECKS_PER_DAY, DEFAULT_MAX_PER_CHECK_USD, CheckConfig, FileSpendStore, create_checker
from .guard import Guard, GuardConfig

PLUGIN = "true402-swap-guard"
KEY_ENV = "TRUE402_PAYER_PRIVATE_KEY"
SETTINGS = ("default_chain", "on_caution", "on_unchecked", "allow_tokens", "max_amount_usd", "max_paid_checks_per_day")
log = logging.getLogger(PLUGIN)


def read_config(raw) -> tuple:
    c = raw if isinstance(raw, dict) else {}

    def pick(v, allowed, default):
        return v if v in allowed else default

    def num(v, default):
        return v if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0 else default

    guard = GuardConfig(
        default_chain=pick(c.get("default_chain"), ("base", "ethereum", "bsc"), "base"),
        on_caution=pick(c.get("on_caution"), ("allow", "ask"), "allow"),
        on_unchecked=pick(c.get("on_unchecked"), ("allow", "ask", "block"), "allow"),
        allow_tokens=[x for x in c.get("allow_tokens", []) if isinstance(x, str)] if isinstance(c.get("allow_tokens"), list) else [],
    )
    check = CheckConfig(
        max_amount_usd=float(num(c.get("max_amount_usd"), DEFAULT_MAX_PER_CHECK_USD)),
        max_paid_checks_per_day=int(num(c.get("max_paid_checks_per_day"), DEFAULT_MAX_PAID_CHECKS_PER_DAY)),
    )
    return guard, check


def register(ctx):
    # ctx.get_config(key, default) reads ONE setting under plugins.entries.<id>.settings.
    guard_cfg, check_cfg = read_config({k: ctx.get_config(k, None) for k in SETTINGS})
    # The payer key comes through Hermes' secret route (catalog rule 11), never from a file, and only
    # from this DEDICATED variable — never a generic key another tool may have set. Optional: without it
    # only free checks run.
    from agent.secret_scope import get_secret
    from plugins.plugin_storage import plugin_data_dir

    check_cfg.payer_private_key = get_secret(KEY_ENV) or None
    store = FileSpendStore(plugin_data_dir(PLUGIN) / "spend.json")
    guard = Guard(create_checker(check_cfg, store), guard_cfg, warn=log.warning)

    def pre_tool_call(tool_name, args, task_id="", **kwargs):
        return guard(tool_name, args if isinstance(args, dict) else {})

    ctx.register_hook("pre_tool_call", pre_tool_call)
