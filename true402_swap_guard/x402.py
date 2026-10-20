"""Pay any true402 stall over x402 and return its JSON.

The whole protocol, in one function: POST → 402 with payment terms → sign an EIP-3009 USDC
authorization → retry with an X-PAYMENT header → 200. No accounts, no API keys; the wallet is the
identity. USDC on Base, gas sponsored by the facilitator (the payer needs only USDC, not ETH).

Safety: the client REFUSES to sign anything that isn't USDC-on-Base within a caller-set cap, so a
rogue/compromised endpoint (or a MITM past TLS) can't make the agent authorize an unexpected
asset/network or an excessive amount.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import time
import warnings
from dataclasses import dataclass, field
from typing import Any

import requests
from eth_account import Account
from eth_account.messages import encode_typed_data

from ._client import CLIENT_ID, INSTALL, PACKAGE, VERSION

BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
BASE_NETWORK = "eip155:8453"
BASE_CHAIN_ID = 8453
DEFAULT_BASE_URL = "https://true402.dev/api"
DEFAULT_RPC_URL = "https://mainnet.base.org"
_BALANCE_OF_SELECTOR = "0x70a08231"

# Update notice. Every request says which client it is (`true402-<id>/<version>`); when a newer release
# exists, true402 answers with `X-True402-Client-Latest` and `X-True402-Client-Update`
# (`recommended` | `required`), and we warn ONCE per process.
#
# The message is built HERE, from this package's own name and install command. Only a strictly
# validated version number is taken from the response — `base_url` can point at any seller, and
# printing a server's free text would let a hostile one tell the user to install something else.
USER_AGENT = f"true402-{CLIENT_ID}/{VERSION} (+https://true402.dev/integrations)"
_VERSION_RE = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}$")
_update_notice_shown = False


def _is_true402(url: str) -> bool:
    try:
        from urllib.parse import urlparse

        host = urlparse(url).hostname or ""
    except Exception:
        return False
    return host == "true402.dev" or host.endswith(".true402.dev")


def update_notice(headers, from_url: str = DEFAULT_BASE_URL) -> "str | None":
    """The line to show for a response's headers, or None. Never raises.

    Only true402 itself may say we are out of date: any other seller could otherwise make this client
    print a fake "security fix pending" (it could not change what gets installed — that command is
    ours — but it could alarm the user).
    """
    if not _is_true402(from_url):
        return None
    try:
        latest = (headers.get("x-true402-client-latest") or "").strip()
        required = headers.get("x-true402-client-update") == "required"
    except Exception:
        return None
    if not _VERSION_RE.match(latest):
        return None
    if tuple(int(x) for x in latest.split(".")) <= tuple(int(x) for x in VERSION.split(".")):
        return None
    if required:
        return f"[true402] {PACKAGE} {VERSION} has a security fix pending - update to {latest}: {INSTALL}"
    return f"[true402] {PACKAGE} {latest} is available (you have {VERSION}): {INSTALL}"


def _note_update(response, from_url: str) -> None:
    global _update_notice_shown
    if _update_notice_shown:
        return
    line = update_notice(getattr(response, "headers", None) or {}, from_url)
    if not line:
        return
    _update_notice_shown = True
    # MUST NOT raise. This runs after the PAID request: under `-W error` (or pytest's
    # `filterwarnings = error`) a warning becomes an exception, and the caller would be charged and
    # lose the answer. A notice is never worth that.
    try:
        warnings.warn(line, stacklevel=3)
    except Exception:
        pass


@dataclass
class PayOpts:
    """Configuration for paying true402 stalls."""

    payer_private_key: str = field(repr=False)
    """A Base wallet private key holding a little USDC (the payer). Never shown in ``repr()``."""
    base_url: str = DEFAULT_BASE_URL
    rpc_url: str = DEFAULT_RPC_URL
    max_amount_usd: float = 0.25
    """Hard ceiling, in USDC, on a single signed payment. The client refuses a 402 demanding more.

    Set above the server's own per-request ceiling (MAX_REQUEST_PRICE_USD, currently $0.20 in
    production) so a legitimately-priced stall can never be blocked by this default. $0.10 was
    silently below the catalog's own top price (keyword-volume, $0.15) and had zero headroom
    against the next one up (backlinks, $0.10 exactly).
    """
    timeout: float = 30.0
    """Deadline for the 402 probe and the RPC balance read."""

    paid_timeout: float = 120.0
    """Deadline for the PAID request — deliberately far longer than `timeout`.

    The server settles on a 2xx, so abandoning a merely SLOW paid response means the buyer was
    charged and got nothing. token-report legitimately takes tens of seconds; 30s was the same
    value as the probe and could cut a completed, settled call short.
    """

    @classmethod
    def from_env(cls, **overrides: Any) -> "PayOpts":
        """Build from PAYER_PRIVATE_KEY / TRUE402_BASE_URL / BASE_RPC_URL env vars."""
        key = overrides.pop("payer_private_key", None) or os.environ.get("PAYER_PRIVATE_KEY", "")
        return cls(
            payer_private_key=key,
            base_url=overrides.pop("base_url", None) or os.environ.get("TRUE402_BASE_URL", DEFAULT_BASE_URL),
            rpc_url=overrides.pop("rpc_url", None) or os.environ.get("BASE_RPC_URL", DEFAULT_RPC_URL),
            **overrides,
        )



# How long the signed USDC authorization stays broadcastable.
#
# ``maxTimeoutSeconds`` comes from the server being paid. ``int()`` already saved these two packages
# from the string-concatenation bug their TypeScript siblings had, but nothing bounded the value: a
# hostile or misconfigured 402 quoting ``999999999`` kept a signed, claimable transfer authorization
# alive for three decades. Amount, asset, network, recipient and the single-use nonce are pinned
# already — the window is the payer's last remaining protection.
MIN_AUTH_WINDOW_S = 30
MAX_AUTH_WINDOW_S = 600
DEFAULT_AUTH_WINDOW_S = 120


def auth_window_seconds(raw):
    """Seconds the authorization stays valid: coerced, bounded, and never trusting the server.

    Garbage falls back to the default instead of raising — refusing to pay over a malformed hint is
    a worse outcome than paying with a sane window. Exercised by ``src/published-clients.test.ts``,
    the only test covering these packages.
    """
    if isinstance(raw, bool) or not isinstance(raw, (int, str)):
        return DEFAULT_AUTH_WINDOW_S
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_AUTH_WINDOW_S
    if n <= 0:
        return DEFAULT_AUTH_WINDOW_S
    return min(MAX_AUTH_WINDOW_S, max(MIN_AUTH_WINDOW_S, n))


def _is_secure_url(url: str) -> bool:
    """May a signed payment be sent here? https, or plain http to THIS machine for development.

    Decided on the PARSED hostname: the prefix regex this replaced also accepted
    ``http://localhost:x@evil.example/`` (userinfo first, then the real host) and paid it in cleartext.
    """
    from urllib.parse import urlparse

    try:
        u = urlparse(url)
        host = u.hostname
    except ValueError:
        return False
    scheme = (u.scheme or "").lower()
    return scheme == "https" or (scheme == "http" and host in ("localhost", "127.0.0.1", "::1"))


def _refuse_redirect(response, url: str) -> None:
    """Redirects are never followed.

    ``requests`` re-sends a 307/308 with the same method, body AND headers — PAYMENT-SIGNATURE
    included — to wherever ``Location`` points, https to http included, so following one would hand a
    signed, claimable authorization to a host this client never vetted. Every request passes
    ``allow_redirects=False`` and any 3xx is an error.
    """
    if 300 <= response.status_code < 400:
        raise RuntimeError(
            f"{url} answered HTTP {response.status_code}: server redirected; refusing to send a payment elsewhere"
        )


_AMOUNT_RE = re.compile(r"[0-9]+", re.ASCII)


def _atomic_amount(raw) -> int:
    """The 402's amount as a positive integer of USDC base units, or raise.

    Digits only: ``int()`` alone would also take ``"1_000"``, ``" 12 "``, ``"-5"``, a float (silently
    truncated) and non-ASCII digits such as ``"١٢"``.
    """
    if isinstance(raw, bool):
        raise ValueError("402 carries no positive payment amount — refusing to sign")
    if isinstance(raw, int):
        value = raw
    elif isinstance(raw, str) and _AMOUNT_RE.fullmatch(raw):
        value = int(raw)
    else:
        raise ValueError("402 carries no positive payment amount — refusing to sign")
    if value <= 0:
        raise ValueError("402 carries no positive payment amount — refusing to sign")
    return value


def _usdc_balance(rpc_url: str, holder: str, timeout: float) -> int:
    data = _BALANCE_OF_SELECTOR + holder[2:].rjust(64, "0")
    body = {"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"to": BASE_USDC, "data": data}, "latest"]}
    r = requests.post(
        rpc_url, json=body, timeout=timeout, headers={"content-type": "application/json"}, allow_redirects=False
    )
    r.raise_for_status()
    return int(r.json()["result"], 16)


def sign_payment(accept: dict, opts: PayOpts) -> str:
    """Sign an EIP-3009 authorization for the given 402 `accepts[]` entry → base64 PAYMENT-SIGNATURE value (x402 v2)."""
    key = opts.payer_private_key
    if not key:
        raise ValueError("no payer_private_key set — cannot pay (set PAYER_PRIVATE_KEY or PayOpts.payer_private_key)")
    if not key.startswith("0x"):
        key = "0x" + key
    account = Account.from_key(key)

    network = accept.get("network")
    if network != BASE_NETWORK:
        raise ValueError(f'unexpected payment network "{network}" (expected {BASE_NETWORK}) — refusing to sign')
    asset = accept.get("asset", "")
    if asset.lower() != BASE_USDC.lower():
        raise ValueError(f"unexpected payment asset {asset} (expected Base USDC) — refusing to sign")

    raw_amount = accept.get("amount")
    value = _atomic_amount(raw_amount if raw_amount is not None else accept.get("maxAmountRequired"))
    cap_atomic = round(opts.max_amount_usd * 1e6)
    if value > cap_atomic:
        raise ValueError(f"402 demands {value} USDC base units, over the ${opts.max_amount_usd} cap — refusing to sign")

    # The balance pre-check is ADVISORY: the server verifies the balance itself and charges nothing
    # when it is short, so an RPC that cannot answer (the free public endpoint rate-limits) must not
    # abort a payable call.
    try:
        held = _usdc_balance(opts.rpc_url, account.address, opts.timeout)
    except Exception:
        held = None
    if held is not None and held < value:
        raise ValueError(f"payer {account.address} holds {held} < {value} USDC base units — fund it")

    now = int(time.time())
    valid_before = now + auth_window_seconds(accept.get("maxTimeoutSeconds"))
    nonce = "0x" + secrets.token_hex(32)
    extra = accept.get("extra") or {}
    authorization = {
        "from": account.address,
        "to": accept["payTo"],
        "value": value,
        "validAfter": now - 60,
        "validBefore": valid_before,
        "nonce": bytes.fromhex(nonce[2:]),
    }
    signable = encode_typed_data(
        domain_data={
            "name": extra.get("name", "USD Coin"),
            "version": extra.get("version", "2"),
            "chainId": BASE_CHAIN_ID,
            "verifyingContract": BASE_USDC,
        },
        message_types={
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce", "type": "bytes32"},
            ],
        },
        message_data=authorization,
    )
    signature = Account.sign_message(signable, key).signature.hex()
    if not signature.startswith("0x"):
        signature = "0x" + signature

    payment = {
        "x402Version": 2,
        "accepted": accept,
        "payload": {
            "signature": signature,
            "authorization": {
                "from": authorization["from"],
                "to": authorization["to"],
                "value": str(value),
                "validAfter": str(authorization["validAfter"]),
                "validBefore": str(authorization["validBefore"]),
                "nonce": nonce,
            },
        },
    }
    import base64

    return base64.b64encode(json.dumps(payment).encode()).decode()


def pay_stall(path: str, payload: dict, opts: PayOpts) -> Any:
    """POST `payload` to a true402 stall path (e.g. '/v1/base/token-report'), paying over x402 if asked.

    If the first response is 200 (a free-trial call), returns it without paying. If it's 402, signs and
    retries. Raises on any other status or on a refused/insufficient payment.
    """
    url = opts.base_url.rstrip("/") + path
    headers = {"content-type": "application/json", "user-agent": USER_AGENT}
    first = requests.post(url, json=payload, headers=headers, timeout=opts.timeout, allow_redirects=False)
    _note_update(first, url)
    _refuse_redirect(first, url)
    # Any 2xx is a served response, and the gate settles on 2xx — these must agree.
    if 200 <= first.status_code < 300:
        return first.json()  # served free (free trial) — no payment needed
    if first.status_code != 402:
        raise RuntimeError(f"expected HTTP 402 from {path}, got {first.status_code}: {first.text[:200]}")

    challenge = first.json()
    accepts = challenge.get("accepts") or []
    # true402 quotes MORE THAN ONE rail and both carry scheme "exact" — EVM and Solana. Matching on
    # scheme alone returns whatever the server listed FIRST, which works only because the server
    # deliberately keeps EVM at accepts[0]; that invariant lives in another codebase and a published
    # client already installed cannot be hot-fixed if it moves. The network is REQUIRED: an entry
    # that does not name its chain is not one this client can pay.
    accept = next(
        (a for a in accepts if a.get("scheme") == "exact" and a.get("network") == BASE_NETWORK),
        None,
    )
    if not accept:
        raise RuntimeError(
            f"no payable x402 requirement in the 402 — this client settles USDC on {BASE_NETWORK} only"
        )

    # Never send a signed payment over cleartext: an on-path observer could lift the authorization and
    # race it to settlement. Localhost is allowed for development.
    if not _is_secure_url(url):
        raise RuntimeError(f"refusing to send a signed payment over cleartext ({url}) - use https")
    x_payment = sign_payment(accept, opts)
    paid = requests.post(
        url,
        json=payload,
        headers={**headers, "PAYMENT-SIGNATURE": x_payment},
        timeout=opts.paid_timeout,
        allow_redirects=False,
    )
    _note_update(paid, url)
    _refuse_redirect(paid, url)
    if not 200 <= paid.status_code < 300:
        raise RuntimeError(
            f"paid request to {path} failed (HTTP {paid.status_code}): the server reported failure — "
            f"a seller following x402 settles only on a 2xx: {paid.text[:200]}"
        )
    return paid.json()
