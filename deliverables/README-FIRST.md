# WireGuard validation harness — deliverables

Prepared 2026-10-11 (UTC). Five files, in the order you probably want them.

| File | What it is |
|---|---|
| `WireGuard-test-report.md` | What was actually measured, on which runner/kernel, with timestamps. Start here. |
| `WireGuard-deployment-guide.md` | How to stand up a real server and a real client config, field by field. |
| `wg-client.conf.template` | **A template, not a working configuration.** See the warning in the file. |
| `WireGuard-security-review.md` | Threat model, key handling, what the leak audit proves. |
| `WireGuard-feasibility.md` | Why a GitHub-hosted runner can never be the server half of a VPN, with sources. |

## The one thing to understand before using any of this

A GitHub-hosted runner **can** speak WireGuard, and this repository proves it: a real
kernel-level handshake, real ChaCha20-Poly1305 transport, and real HTTPS traffic
carried through the tunnel — all reproduced on every commit by CI.

A GitHub-hosted runner **cannot** be a VPN server. It is an ephemeral VM behind
provider NAT with no inbound reachability and no stable address, and using Actions as
a hosted service endpoint is outside the GitHub Terms for Additional Products and
Features. That is why the deliverable is a *test harness* plus a *deployment kit*, and
why the client configuration here still has placeholders: the endpoint address and the
key material can only come from a host you control.

## Do not

* Do not load `wg-client.conf.template` into a WireGuard client and expect it to
  connect. It contains `{{PLACEHOLDER}}` values by design.
* Do not paste a rendered config into a ticket, a chat or a repository. It contains a
  private key and is a credential.
