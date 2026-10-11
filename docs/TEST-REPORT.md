# Test report

What was actually observed, when, and on what. Every number here was read back from a
recorded run. Checks that were not executed are listed with the reason, and **no
handshake is claimed anywhere on this page unless a non-zero `latest-handshakes`
value was read from the kernel**.

---

## 1. Summary

| Run | Where | When (UTC) | Result |
|---|---|---|---|
| CI harness, `ubuntu-24.04` | GitHub-hosted runner, kernel `6.17.0-1022-azure`, image `ubuntu24-20261004.327.1` | 2026-10-11 12:02:01 – 12:02:56 | **PASS 58, FAIL 0, UNTESTED 0, SKIP 0** |
| CI harness, `ubuntu-22.04` | GitHub-hosted runner, kernel `6.8.0-1064-azure`, image `ubuntu22-20261004.315.1` | 2026-10-11 12:02:02 – 12:02:58 | **PASS 58, FAIL 0, UNTESTED 0, SKIP 0** |
| Static analysis | GitHub-hosted runner | 2026-10-11 12:02 | success (ShellCheck, `compileall` + AST, yamllint, 47 unit tests, 10 workflow policy tests) |
| Local harness | Development sandbox, kernel `6.1.158+`, 2 CPUs | 2026-10-11 11:56 | PASS 51, FAIL 1, UNTESTED 5, SKIP 1 — the single FAIL and all five UNTESTED cases are sandbox limitations, itemised in §5 |

Workflow runs: *WireGuard validation* `38137734106`, *WireGuard static analysis*
`38137734140`, both on commit `1f1b180`. Evidence is reproduced from the check-run
annotations of that run and from `artifacts/checks.ndjson` in the job artifacts.
The previous green pair, `38137396217` / `38137396260` on `2bd00ff`, produced the same
58 PASS on both legs.

Early CI runs failed and were the most valuable runs of the project — §4 lists what
they caught.

### Local unit tests

```
$ bash tests/run-unit-tests.sh
unit tests: 47 passed, 0 failed        # config validator, secret scanner (both
                                       # provenance modes), renderer, DNS helpers,
                                       # wg output redaction, shipped template,
                                       # documentation drift check

$ bash tests/check-workflows.sh
workflow checks: 10 passed, 0 failed   # pinned SHAs, least privilege, no
                                       # pull_request_target, per-job timeouts,
                                       # no untrusted interpolation, no secret echoes
```

---

## 2. The handshake, and what makes it evidence

The central claim of this project is that the configuration and data path work. The
observation behind it, copied verbatim from the check record:

```
HS-01  latest-handshakes=1791720140 (2026-10-11T12:02:20Z), waited 0s     [ubuntu-24.04]
HS-01  latest-handshakes=1791720138 (2026-10-11T12:02:18Z), waited 0s     [ubuntu-22.04]
HS-02  latest-handshakes=<same value read independently on the peer>
HS-03  client rx=220B tx=308B         <- encrypted transport, not just negotiation
```

Why this is not "the script exited zero":

* `HS-01`/`HS-02` read `latest-handshakes` from the kernel via `wg show` on **both**
  sides and require the same non-zero timestamp. A zero value means no handshake, and
  the check fails.
* `HS-03` reports the rx/tx byte counters, which only advance when authenticated
  transport packets have been decrypted.
* `TUN-05` confirms the server was listening on `0.0.0.0:51820` inside its namespace
  before the handshake was attempted, so the handshake cannot have happened over a
  different path.
* `REC-01` is the negative control: with a deliberately wrong preshared key, **no
  handshake occurred within 12 s**. Without that control, "a handshake happened" would
  not distinguish a correct PSK from an ignored one.

---

## 3. Per-area results (CI, both legs identical unless noted)

### 3.1 Dependencies and platform — `DEP-00..03`, `PRE-01..06`

```
DEP-01  apt-get install wireguard-tools iproute2 iptables dnsutils iputils-ping curl jq
DEP-02  wg ip jq python3          DEP-03  dig iptables ss ping curl
PRE-01  6.17.0-1022-azure (24.04) / 6.8.0-1064-azure (22.04)
PRE-02  already root (euid=0)
PRE-03  created wgpf0 type wireguard; kernel module wireguard available
PRE-04  created and destroyed network namespace wgpf-ns; netlink namespace support present
PRE-05  UDP/53 to 1.1.1.1 answered with 61 bytes
PRE-06  ephemeral Azure VM behind provider NAT; no static public IP on standard runners
```

`PRE-03` is the load-bearing one: the **kernel** WireGuard interface was created and
removed before any test depended on it, which is why every later check exercises the
in-kernel data path rather than a userspace fallback. `DEP-01` performed a real
`apt-get install` on the runner — dependency installation is genuinely tested there,
while in the local sandbox it is recorded `UNTESTED` because egress to the distro
mirror is blocked.

### 3.2 Key generation and secure storage — `KEY-01..06`

```
KEY-01  public=/vE2T4Ob... (private key never logged)
KEY-02  public=W8TK66Hd... (private key never logged)
KEY-03  32-byte PSK stored at 0600
KEY-04  all 0600
KEY-05  server/client keys differ
KEY-06  scan clean
```

Only public keys appear in the report; the private keys are never logged by anything
in the harness. `KEY-06` scans the whole run's output for key material.

### 3.3 Configuration validity — `CFG-01..07`

```
CFG-01  placeholders only                       <- templates contain no real values
CFG-02  18 documented variables, all resolvable
CFG-08  valid with --allow-placeholders, rejected as a live config
CFG-03  server.conf + client.conf produced
CFG-04  both files exist at the expected paths
CFG-05  required keys, PSK, AllowedIPs, MTU validated
CFG-06  tight permissions enforced (0600 configs, 0700 key directory)
CFG-07  placeholder scan clean
```

Validation runs **before** any service starts, so a malformed file cannot half-start a
tunnel. The same validator rejects placeholder values unless `--allow-placeholders` is
passed explicitly — that is what stops a template from being mistaken for a deployable
configuration.

### 3.4 Tunnel construction and handshake — `TUN-01..06`, `HS-01..04`

```
TUN-01  10.13.13.1:53            <- test resolver listening inside the tunnel
TUN-02  wg0 10.13.13.1/24 in netns wgsrv
TUN-03  wg0 10.13.13.2/24 in netns wgcli
TUN-04  1 peer configured on each side
TUN-05  0.0.0.0:51820 inside netns wgsrv
TUN-06  MASQUERADE present in netns wgsrv     <- forwarding/NAT for the egress test
HS-04   diagnostics/wg-*-dump.txt (key column redacted)
```

### 3.5 Routing and DNS — `RT-01..04`, `DNS-01..03`

```
RT-01  10.13.13.1 dev wg0 src 10.13.13.2 uid 0        <- tunnel subnet goes through the tunnel
RT-02  192.168.77.2 dev vethcli src 192.168.77.3      <- the transport peer does NOT
RT-03  1.1.1.1 -> 1.1.1.1 dev wg0 src 10.13.13.2      <- full-tunnel default route
RT-04  192.168.77.2 dev vethcli src 192.168.77.3      <- exclusion re-verified after the default route
DNS-01  gateway.wg.internal A -> 10.13.13.1 via dig; resolver 10.13.13.1 is only reachable through wg0
DNS-02  negative control fails as expected, so DNS-01 demonstrates tunnel usage
DNS-03  example.com -> 104.20.23.154 (24.04) / 172.66.x.x (22.04)     <- forwarded upstream
```

`RT-04` matters because `RT-03` installs a default route through the tunnel: without
`RT-04`, a harness could "pass" routing tests while having silently cut off the
transport path to its own peer. `DNS-02` is the control that makes `DNS-01` meaningful.

### 3.6 Connectivity — `CON-01..05`

```
CON-01  3 packets transmitted, 3 received, 0% packet loss,
        rtt min/avg/max/mdev = 0.199/0.229/0.257/0.023 ms      <- ICMP inside the tunnel
CON-02  echo server replied through wg0                        <- UDP round trip
CON-03  GET /health.txt -> 200 ok                              <- TCP/HTTP
CON-04  https://api.github.com/zen via wg0 -> "Keep it logically awesome."   [24.04]
CON-04  https://api.github.com/zen via wg0 -> "Mind your words, they are
        important."                                                        [22.04]
CON-05  payload 1392B carried (MTU 1420)                       <- DF bit set, no fragmentation
```

`CON-04` is the strongest end-to-end statement in the report: a real HTTPS request
from the client namespace reached a public host **through `wg0` and the server-side
NAT**, and a 200 response came back. `CON-05` sends a 1392-byte payload with the DF bit
set, which is the largest packet that fits inside a 1420-byte tunnel MTU once headers
are accounted for — it would fail on an MTU miscalculation.

### 3.7 Failure recovery — `REC-01..04`

```
REC-01  no handshake within 12s with a wrong PSK (fail-closed, as WireGuard specifies)
REC-02  handshake re-established within 30s without rebuilding the interface
REC-03  ping over a dead endpoint returned rc=1 within the bounded timeout:
        1 packets transmitted, 0 received, 100% packet loss, time 0ms
REC-04  recovered in 0s reusing the existing session (no rekey needed)
```

This is the section that required the most care, because the tempting assertion is
wrong. WireGuard keeps a session alive for up to 180 seconds; requiring a *fresh*
handshake after an endpoint change would fail against a perfectly working tunnel.
`REC-04` therefore asserts **reachability**, and reports whether it observed a new
handshake or a reused session. It is a pass either way, and the distinction is
recorded rather than hidden.

`REC-03` is bounded on purpose: a dead endpoint must fail fast and observably, and it
does (rc=1 within the timeout), which is what makes the recovery in `REC-04`
meaningful.

### 3.8 Cleanup and leak audit — `CLN-01..04`, `SEC-01..05`

```
CLN-01  no wgsrv/wgcli/wgctl namespaces remain
CLN-02  root namespace is clean
CLN-03  state directory /run/wg-harness removed
CLN-04  no orphaned DNS/UDP/HTTP servers
SEC-01  no private/preshared key material detected (heuristic + provenance)  (working tree)
SEC-02  no private/preshared key material detected (heuristic + provenance)  (artifact tree)
SEC-03  no private/preshared key material detected (heuristic + provenance)  (job summary)
SEC-04  no secret variables exported
SEC-05  no floating tags in workflow `uses:` lines
```

`SEC-01..03` are the reason the harness can be trusted to publish its own
diagnostics. They run after cleanup, on the exact trees that will be published, and
they use the provenance pass (`--secrets-from`) in addition to the heuristic pass.

---

## 4. Defects found and fixed during validation

These are real failures the harness caught in its own code. They are listed because a
test report that only shows green is not a test report.

| # | Symptom | Root cause | Fix |
|---|---|---|---|
| 1 | `SEC-01` + `STEP-10` FAIL on CI: key material in `diagnostics/topology.txt` and `recovery-broken-peer.txt` | The `wg show dump` redactor masked only column 1, but a peer line carries the **preshared key in column 2**. The scanner should have caught it, but skipped any line containing `<redacted>` — masking one column hid the other | Field-position redaction (`wg_redact_dump`); the scanner no longer skips partially redacted lines |
| 2 | The same run reported public keys as leaks | The public-context regex only matched `public_key`, never `public key:`, which is how `wg show` renders it | Recogniser accepts `PublicKey =`, `public_key =`, `public key:`, `peer: <key>`; the bare word "public" is no longer accepted as evidence |
| 3 | The annotation step produced nothing on the first CI attempt | A quoting error turned the `jq` program into invalid syntax and `jq` failed silently in the pipeline | Rewritten in Python; escaping is now regression-tested |
| 4 | `STEP-07` failed with rc=127 | A refactor removed two helper functions that the step still called | Helpers restored; ShellCheck (SC2034) would have caught the dead variable earlier |
| 5 | Annotation titles were truncated (`Recovery, cleanup and leaks` → `Recovery`) | A workflow-command title ends at the first comma | Commas escaped as `%2C` |
| 6 | `PRE-02..05` had empty details | The probes were silent on success, so a passing check recorded nothing | Probes now print their own one-line proof |
| 7 | `0% packet loss` rendered as `0 packet loss` in annotations | `%` was deleted instead of escaped (`%25`) | Escaping fixed |
| 8 | `SEC-01` FAILed on CI while `SEC-02` passed on the same commit, and the check detail said only "secret material detected" | Two compounding problems. The audit's provenance pass never ran at all: `09-cleanup.sh` deletes the key directory *before* the audit, so `--secrets-from` was silently inert and only the weaker heuristic pass was ever executing. And the finding itself was written to a log rather than into the check, so it could not be read back | `02-keygen.sh` now writes a manifest of SHA-256 **digests** into the artifact tree; digests are one-way, so the manifest is safe to publish, and provenance survives key deletion. The check detail now carries the `LEAK` lines, and states which passes ran — "heuristic only" can no longer be mistaken for full coverage |
| 9 | `wg_redact_leading_key` appeared to work but redacted nothing | `mawk 1.3.4`, the `/usr/bin/awk` on Debian and Ubuntu, does not implement `{n}` interval expressions, so `/^[A-Za-z0-9+/]{42}…/` matched nothing — silently. This is the same class of bug as #1: a redactor that fails open | Length- and character-based matching instead of intervals, and a unit test that feeds a real 44-character key through the redactor |

---

## 5. UNTESTED and SKIP cases, and why

An `UNTESTED` row means the observation was never made. It is never counted as a pass.

| Check | Local sandbox | CI | Reason / disposition |
|---|---|---|---|
| `DEP-00` package installation | UNTESTED | PASS | Sandbox has no reachable distro mirror; CI performs a real `apt-get install` |
| `DEP-03` optional tools | UNTESTED (`dig`, `iptables` missing) | PASS | Sandbox limitation |
| `TUN-06` NAT/forwarding | UNTESTED (`iptables` missing) | PASS | Sandbox limitation |
| `DNS-03` forwarded resolution | UNTESTED (no upstream) | PASS | Depends on outbound UDP/53, blocked in the sandbox |
| `CON-04` internet egress through the tunnel | UNTESTED (no `iptables`) | PASS | Depends on NAT, which needs `iptables` |
| `SEC-03` job summary scan | SKIP (no summary file outside CI) | PASS | Only meaningful inside a workflow |
| `PRE-05` outbound UDP/53 | **FAIL** | PASS | Sandbox filters UDP/53 egress on the test path. Recorded as a failure, not reclassified — the check is correct and the environment is the limitation |
| `PRE-06` inbound reachability | PASS | PASS | Asserted as a *catalogue* fact: no inbound path exists, which is why the runner cannot serve |

**No case in this project's checklist is left untested by design.** Every one of the
ten required areas has at least one check that ran and observed a result on both CI
legs. The remaining `UNTESTED` rows are environment limitations of the development
sandbox, and each is reproduced as a pass on the hosted runners.

---

## 6. What this report does *not* claim

* It does **not** claim a public, internet-reachable VPN endpoint exists. The
  handshake and the tunnelled traffic are real, but they travel over a `veth` link
  between two namespaces inside one VM. `PRE-06` records that no inbound path exists.
* It does **not** claim the runner can serve as a VPN server, or that two workflows
  could cooperate into one. [`FEASIBILITY.md`](FEASIBILITY.md) §2.3 and §3 explain why
  both fail, and §4 gives the architecture that works.
* It does **not** claim a client configuration produced from `examples/` is ready to
  use. Until you supply your own endpoint and keys it is a template with
  placeholders — see [`DEPLOYMENT.md`](DEPLOYMENT.md) §4 for how to tell the
  difference.
* It does **not** claim performance. The latency numbers above measure a `veth` link
  inside one VM; they say nothing about throughput over a real network.
