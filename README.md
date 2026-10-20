# true402 swap guard for Hermes

**A Hermes plugin that checks every token your agent is about to buy, and blocks the trade when the token is a honeypot or a rug in progress.**

It registers one `pre_tool_call` hook, so it sits in front of *every* way your agent can trade — terminal commands, MCP servers, plugin tools — whatever skill it is following. A skill the agent forgets to follow cannot skip it. The same plugin exists for OpenClaw: [`@true402.dev/openclaw-swap-guard`](https://github.com/true402/openclaw-swap-guard).

```bash
hermes plugins install true402/hermes-swap-guard/true402_swap_guard --enable
```

## What it does

Before a tool call that buys a token, the guard asks [true402](https://true402.dev):

| Chain | Check | Price after the free daily checks |
|---|---|---|
| Base, Ethereum, BSC | `/v1/{chain}/token-report`: an executed buy **and sell** simulation, deployer history, recent liquidity pulls | $0.008 |
| Solana | `/v1/solana/token-safety`: freeze / mint authority, Token-2022 extensions, liquidity | $0.005 |

- **Blocks** only on a definite danger verdict for a token being bought: an EVM token rated *avoid* (cannot be sold, extreme sell tax, liquidity just pulled…), or a Solana mint that can never be sold, can be seized, or is critical risk. The agent gets the reasons and is told not to retry with another tool.
- **Never blocks a sale.** The token you are selling is not checked, and when a command is ambiguous enough that a dangerous token *might* be the one being sold, the guard sends the call to Hermes' approval gate instead of blocking.
- **Lets the trade through** when the token checks out — and, by default, when it could not be checked (true402 unreachable, free checks used up, the address is a wallet rather than a token), logging a warning. Change that with `on_unchecked`.
- Skips majors and stablecoins, reuses a verdict for 10 minutes, and checks up to 5 distinct tokens per call — more is held for approval.
- Answers inside Hermes' 30-second `pre_tool_call` limit (a slower hook would block the tool): all checks of one call run in parallel within 26 s.

Command parsing fails closed: a token is checked on the default chain and on every chain the command names, and anything ambiguous — a `#`, `$'…'`, unbalanced quotes — means every address is checked. A plain-English order that names no address (`"buy $20 of PEPE"`), or a token passed through a shell variable, cannot be checked.

Under unattended runs (cron, the messaging gateway) an approval request fails closed, as Hermes' approval gate always does: nothing is auto-approved.

## Paying for checks

No setup is needed for a few checks a day: the guard uses true402's free daily allowance.

For more, give it a **dedicated, low-balance** Base wallet holding a little USDC (gas is sponsored), as the plugin's `payer_private_key` secret (environment name `TRUE402_PAYER_PRIVATE_KEY`). It is read through Hermes' secret route, never from a file, and never a generic `PAYER_PRIVATE_KEY` another tool may have set. Paid checks also need the declared `eth-account` dependency; without it the guard runs free checks only.

Spending is bounded twice: **at most $0.02 per check** (`max_amount_usd`) and **at most 50 paid checks per UTC day** (`max_paid_checks_per_day`) — at most $1.00 a day by default. The day's count is kept in the plugin's data directory (`<hermes home>/plugin-data/true402-swap-guard/spend.json`), so restarting Hermes does not reset it; if that file cannot be written, no payment is made.

## Settings

Under `plugins.entries.true402-swap-guard.settings`:

| Setting | Default | Meaning |
|---|---|---|
| `default_chain` | `base` | Chain assumed for a `0x` address when the trade names none (`base`, `ethereum`, `bsc`) |
| `on_caution` | `allow` | `ask` = send a *caution* verdict to the approval gate |
| `on_unchecked` | `allow` | `ask` or `block` when a token could not be checked |
| `allow_tokens` | `[]` | Token addresses never checked |
| `max_amount_usd` | `0.02` | Never pay more than this for one check |
| `max_paid_checks_per_day` | `50` | Paid checks per UTC day; after that only free checks run |

## Disclosure

- **Network:** for each token a tool call would buy, the token address and its chain are sent to `true402.dev` (`POST /api/v1/{chain}/token-report` or `/api/v1/solana/token-safety`). Nothing about your prompts, the trade or other tools is sent.
- **Paid checks** (only with the optional key) also send a signed USDC payment authorization, which reveals the paying wallet's **address** to true402; the payment is settled on Base, where it is public. The private key itself never leaves your machine.
- **Local data:** one small file, the day's paid-check count, in the plugin's data directory. No credentials are stored by the plugin.
- No shell commands, no background processes, no telemetry.

## License

MIT
