# Security policy

## Supported versions

`byoai-runtime` is in alpha (`0.x`). Fixes go into the latest release from `main`. There is
no long-term support window before `1.0`.

| Version | Supported |
| ------- | --------- |
| latest `0.x` release | yes |
| older `0.x` releases | no |

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it privately, either way:

- GitHub: [open a private advisory](https://github.com/coriqo/byoai-runtime/security/advisories/new)
  on this repository.
- Email: **security@coriqo.io**.

Include the affected version, the steps to reproduce it, and what an attacker gains. We
acknowledge the report, keep you told while we fix it, and agree the disclosure date with
you. The advisory credits you by name unless you ask us not to.

## What we most want to hear about

This runtime decides, in your own process, whether an agent may call a tool. A way around
that decision matters most:

- **Mandate enforcement** (`byoai.recorder.mandate`, `proxy_gate`, `governed_tool`,
  `denial_latch`): a tool call that goes through when the mandate in force refuses it, under
  `enforce`; a prohibited tool that is not refused; a suspension that does not stop the run.
- **`coriqo-mcp`**: a `tools/call` that reaches the MCP server without being checked, a
  `tools/list` that shows a tool the mandate hides, or a refused call whose arguments still
  reach the server.
- **The signed ledger** (`byoai.recorder.ledger`, `keys`, `checkpoint`): an entry changed,
  removed or reordered without the hash chain or a signed checkpoint showing it; a device key
  exposed or usable by another process.
- **Shield** (the local proxy and the browser extension): text that a policy says to block or
  redact leaving the machine; message text written to the ledger; the extension sending to a
  program other than the Shield it paired with.
- **Credentials**: an API key, a device key or a provider credential written to a log, an
  error message or telemetry.
- **Providers and cache**: a request a provider adapter can be made to send somewhere else
  (SSRF); `byoai:*` writes reaching another application's keys; a filter that widens a query
  beyond what the caller asked for.

## Reported elsewhere

- **The Coriqo service** (the hosted product your runtime reports to): security@coriqo.io.
- **A sealed record that verifies after being changed**: that is the open challenge at
  <https://coriqo.io/break-the-seal.html>, for the verifier at
  [coriqo/coriqo-seal-verifier](https://github.com/coriqo/coriqo-seal-verifier).
