"""Does this tool call BUY a token, and which one, on which chain?

Pure: no network, no Hermes import, so every rule is unit-tested. A port of the OpenClaw guard's
detect.ts (same rules, same tests), so both guards answer the same command the same way.

Fail-closed by construction. Commit review of the TypeScript guard found six ways in a row to make a
hand-rolled shell parser misread a command (quotes, comments, $'…', operators inside quotes), so
nothing here relies on parsing shell correctly. A misreading can only ADD checks, never remove one:
- the command is a trade if ANY part of it uses a trade verb;
- the token is checked on the default chain AND every supported chain named anywhere (comments
  included); an unsupported chain named anywhere is also reported;
- the one exemption (the token being SOLD is not checked, so a rug's holder can still exit) applies only
  when the command is unambiguous: no `#`, no `$'…'`, balanced quotes, and every mention of the token
  on the sell side. Otherwise every address is checked.
Known limit: a token passed through a shell variable is not seen.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional

CHAINS = ("base", "ethereum", "bsc", "solana")
EVM_CHAINS = ("base", "ethereum", "bsc")
UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class TradeTarget:
    chain: str  # one of CHAINS, or UNSUPPORTED (a chain true402 does not serve: reported, never guessed)
    token: str
    # The command also names this token on the SELL side in an ambiguous way: a danger verdict then
    # asks the user instead of blocking (blocking the exit from a rug would trap its holder).
    maybe_sold: bool = False


EVM_ADDRESS = re.compile(r"0x[a-fA-F0-9]{40}\b")
# Base58, 32–44 characters: a Solana mint. Only trusted where a parameter or flag NAMES a token.
SOLANA_MINT = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")

TRADE_VERB = re.compile(
    r"\b(swap|swaps|buy|buys|trade|snipe|ape|purchase|enter|market-buy|limit-buy)\b|tradr-enter|--token-out|--output-mint|--buy-token",
    re.I,
)
TRADE_TOOL = re.compile(r"(swap|buy|trade|snipe|purchase|order)", re.I)

OUT_KEYS = ["tokenout", "token_out", "outputmint", "output_mint", "outputtoken", "output_token", "totoken", "to_token",
            "buytoken", "buy_token", "tokentobuy", "mintout", "outmint", "to"]
TOKEN_KEYS = ["token", "tokenaddress", "token_address", "mint", "ca", "contract", "contractaddress", "contract_address",
              "address", "asset"]
PARTY_KEYS = re.compile(r"recipient|receiver|wallet|owner|sender|spender|from_address|payer|beneficiary|account|user", re.I)

IN_FLAGS = ["token-in", "input-mint", "from-token", "sell-token", "from", "in"]
OUT_FLAGS = ["token-out", "output-mint", "to-token", "buy-token", "mint", "token", "ca"]

SKIP = {
    "0x0000000000000000000000000000000000000000",
    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",  # native-asset sentinel
    "0x4200000000000000000000000000000000000006",  # WETH (Base)
    "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",  # USDC (Base)
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",  # WETH (Ethereum)
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC (Ethereum)
    "0xdac17f958d2ee523a2206206994597c13d831ec7",  # USDT (Ethereum)
    "0x6b175474e89094c44da98b954eedeac495271d0f",  # DAI (Ethereum)
    "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",  # WBNB
    "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",  # USDC (BSC)
    "0x55d398326f99059ff775485246999027b3197955",  # USDT (BSC)
    "so11111111111111111111111111111111111111112",  # wrapped SOL
    "epjfwdd5aufqssqem2qn1xzybapc8g4wegggkzwytdt1v",  # USDC (Solana)
    "es9vmfrzacermjfrf4h2fyd4kconky11mcce8benwnyb",  # USDT (Solana)
}

CHAIN_NAMES = {
    "base": "base", "8453": "base", "eip155:8453": "base",
    "ethereum": "ethereum", "eth": "ethereum", "mainnet": "ethereum", "1": "ethereum", "eip155:1": "ethereum",
    "bsc": "bsc", "bnb": "bsc", "binance": "bsc", "56": "bsc", "eip155:56": "bsc",
    "solana": "solana", "sol": "solana",
}

_SEGMENTS = re.compile(r";|&&?|\|\|?|\n")


def _read_chain(v: Any) -> Optional[str]:
    if v is None or v == "":
        return None
    return CHAIN_NAMES.get(str(v).lower().strip(), UNSUPPORTED)


def _skip(token: str) -> bool:
    return token.lower() in SKIP


def _is_evm(s: str) -> bool:
    return re.fullmatch(r"0x[a-fA-F0-9]{40}", s) is not None


def _flags(seg: str, names: list[str]) -> list[str]:
    out: list[str] = []
    for n in names:
        out += [m.group(1) for m in re.finditer(rf"--{re.escape(n)}(?:=|\s+)['\"]?([^\s'\"]+)", seg, re.I)]
    return out


def _command_of(params: dict) -> Optional[str]:
    for k in ("command", "cmd", "script", "input"):
        if isinstance(params.get(k), str):
            return params[k]
    return None


def detect_trade(tool_name: str, params: dict, default_chain: str = "base") -> list[TradeTarget]:
    """The tokens a tool call would buy, or [] when it is not a buy (or names no token we can check)."""
    found: list[TradeTarget] = []
    cmd = _command_of(params)
    # Any tool's command-like string is read: a false positive costs one check and never blocks alone.
    if cmd is not None:
        found += _from_command(cmd, default_chain)
    # A trade tool is read from its structured parameters too, so a string field that happens to be
    # called `input` can never hide them.
    if TRADE_TOOL.search(tool_name or ""):
        found += _from_params(params, default_chain)
    seen: set[str] = set()
    out: list[TradeTarget] = []
    for t in found:
        k = f"{t.chain}:{t.token.lower()}"
        if k not in seen:
            seen.add(k)
            out.append(t)
    return out


def _awal_sold(seg: str) -> Optional[str]:
    """`awal trade <amount> <from> <to>`: <from> is what is being sold (awal's syntax only)."""
    if not re.search(r"\bawal\b", seg):
        return None
    m = re.search(r"\btrade\s+(\S+)\s+(\S+)\s+(\S+)", seg)
    return m.group(2).replace("'", "").replace('"', "") if m else None


def _from_command(cmd: str, default_chain: str) -> list[TradeTarget]:
    if not TRADE_VERB.search(cmd):
        return []

    named = [_read_chain(v) for v in _flags(cmd, ["chain", "network"])]
    supported = [c for c in dict.fromkeys(named) if c is not None and c != UNSUPPORTED]
    unsupported_named = UNSUPPORTED in named
    # The default chain is ALWAYS checked: a chain flag (perhaps inside a comment) can add chains but
    # never remove the one the token most likely lives on. Named chains first.
    evm_chains = list(dict.fromkeys([c for c in supported if c != "solana"] + [default_chain]))

    unambiguous = not re.search(r"#|\$'", cmd) and cmd.count('"') % 2 == 0 and cmd.count("'") % 2 == 0
    sold_any = {v.lower() for v in _flags(cmd, IN_FLAGS)}
    for seg in _SEGMENTS.split(cmd):
        s = _awal_sold(seg)
        if s:
            sold_any.add(s.lower())
    sold: dict[str, int] = {}
    if unambiguous:
        for v in _flags(cmd, IN_FLAGS):
            sold[v.lower()] = sold.get(v.lower(), 0) + 1
        for seg in _SEGMENTS.split(cmd):
            s = _awal_sold(seg)
            if s:
                sold[s.lower()] = sold.get(s.lower(), 0) + 1

    lower = cmd.lower()

    def keep(v: str) -> bool:
        return not _skip(v) and sold.get(v.lower(), 0) < lower.count(v.lower())

    # maybe_sold (danger then ASKS) only where the command really is unclear: an ambiguous command that
    # names the token on the sell side and NO buy flag names it.
    bought_by_flag = {v.lower() for v in _flags(cmd, OUT_FLAGS)}

    def mark(t: TradeTarget) -> TradeTarget:
        tok = t.token.lower()
        if not unambiguous and tok in sold_any and tok not in bought_by_flag:
            return TradeTarget(t.chain, t.token, True)
        return t

    out: list[TradeTarget] = []
    evm = [a for a in dict.fromkeys(m.group(0) for m in EVM_ADDRESS.finditer(cmd)) if keep(a)]
    # Every EVM address that is not a major or the token being sold. A recipient wallet that slips in
    # comes back "not a token", which the guard lets through.
    for chain in evm_chains:
        out += [mark(TradeTarget(chain, a)) for a in evm]
    if unsupported_named:
        out += [mark(TradeTarget(UNSUPPORTED, a)) for a in evm]

    words = list(dict.fromkeys(re.sub(r"^[^=]*=", "", w).replace("'", "").replace('"', "")
                               for w in re.split(r"[\s;|&`()]+", cmd)))
    if "solana" in supported:
        out += [mark(TradeTarget("solana", w)) for w in words if SOLANA_MINT.match(w) and keep(w)]
    elif not supported:
        out += [mark(TradeTarget("solana", v)) for v in _flags(cmd, OUT_FLAGS)
                if SOLANA_MINT.match(v) and not _is_evm(v) and keep(v)]
    return out


def _flatten(params: dict) -> dict:
    """Top-level and one nested level of params, keys normalised; party-like keys dropped."""
    m: dict = {}

    def add(k: str, v: Any) -> None:
        n = re.sub(r"^_+", "", k.lower().replace("-", "_"))
        if PARTY_KEYS.search(n):
            return
        m.setdefault(n, v)
        m.setdefault(n.replace("_", ""), v)

    for k, v in params.items():
        if isinstance(v, dict):
            for k2, v2 in v.items():
                add(str(k2), v2)
        else:
            add(str(k), v)
    return m


def _from_params(params: dict, default_chain: str) -> list[TradeTarget]:
    flat = _flatten(params)
    raw_chain = next((flat[k] for k in ("chain", "network", "chainid", "chain_id") if flat.get(k) is not None), None)
    chain = _read_chain(raw_chain)
    for keys in (OUT_KEYS, TOKEN_KEYS):
        for k in keys:
            v = flat.get(k)
            if isinstance(v, str):
                t = _target(v, chain, default_chain)
                if t:
                    return t
    return []


def _target(raw: str, chain: Optional[str], default_chain: str) -> list[TradeTarget]:
    v = raw.strip()
    if _skip(v):
        return []
    if _is_evm(v):
        c = UNSUPPORTED if chain == UNSUPPORTED else (chain if chain and chain != "solana" else default_chain)
        return [TradeTarget(c, v)]
    # A Solana mint only where a key names a token AND nothing says it is an EVM chain.
    if SOLANA_MINT.match(v) and chain in (None, "solana"):
        return [TradeTarget("solana", v)]
    return []
