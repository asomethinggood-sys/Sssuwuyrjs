# WireGuard validation harness

A WireGuard VPN project that is **built, tested and continuously validated by GitHub
Actions**, with the test evidence published as a workflow artifact and as check-run
annotations on every commit.

The short version of what this repository is:

* a **hermetic two-namespace WireGuard testbed** that runs on a stock GitHub-hosted
  Ubuntu runner and proves a handshake, routing, DNS, ICMP/UDP/TCP, MTU, failure
  recovery and teardown **for real** — not by asserting that a script exited zero;
* a **portable deployment kit** (`examples/`, `scripts/render-config.sh`) for running
  the same server on a host you own, which is the only place a WireGuard server can
  legally and technically live;
* a **feasibility and policy analysis** ([`docs/FEASIBILITY.md`](docs/FEASIBILITY.md))
  explaining why a GitHub-hosted runner can never be the server half of a VPN, with
  the platform behaviour that claim rests on.

> **Honest scope statement.** This repository does **not** run a VPN service for you.
> GitHub-hosted runners are ephemeral VMs behind provider NAT with no inbound
> reachability and no stable public address, and using Actions as a hosted service
> endpoint is outside the GitHub Terms for Additional Products and Features. What the
> harness proves is that the *configuration, key handling, data path and recovery
> behaviour are correct*; you supply the persistent host. See
> [`docs/FEASIBILITY.md`](docs/FEASIBILITY.md) §4.

---

## Status

| Signal | Where it comes from | Result |
|---|---|---|
| Harness checks | `ubuntu-22.04` + `ubuntu-24.04` matrix, workflow *WireGuard validation* | **58 / 58 PASS** on both legs |
| Unit tests | `bash tests/run-unit-tests.sh` | **45 passed, 0 failed** |
| Workflow policy tests | `bash tests/check-workflows.sh` | **10 passed, 0 failed** |
| Static analysis | ShellCheck, `python -m compileall` + AST, `yamllint` | clean |

Per-check evidence for a specific commit lives on that commit's check run
(*Actions → the run → Annotations*) and in the `wireguard-test-report-*` artifacts.
The results reproduced from real runs, with timestamps and raw observations, are in
[`docs/TEST-REPORT.md`](docs/TEST-REPORT.md).

---

## Quick start

### Look at what the harness does without running anything

```bash
sed -n '1,80p'   .github/workflows/wireguard-validation.yml   # the matrix job
less docs/ARCHITECTURE.md                                     # Mermaid diagrams
less docs/TEST-REPORT.md                                      # real observations
```

### Run the whole harness locally

Requires Linux, root (or passwordless `sudo`), `iproute2`, and Python 3.9+. The
harness installs what else it needs.

```bash
git clone https://github.com/asomethinggood-sys/Sssuwuyrjs
cd Sssuwuyrjs
sudo -E env WG_ARTIFACT_DIR="$PWD/artifacts" bash scripts/run-suite.sh
echo "exit=$?"          # non-zero iff at least one check FAILed
less artifacts/test-report.md
```

Everything is safe to run on a workstation: all interfaces live inside two throwaway
network namespaces (`wgsrv`, `wgcli`), are destroyed by an `EXIT` trap, and the
harness verifies afterwards that nothing was left behind (`CLN-01..04`).

Common environment switches:

| Variable | Default | Meaning |
|---|---|---|
| `WG_ARTIFACT_DIR` | `artifacts/` (or `$GITHUB_WORKSPACE/artifacts`) | publishable output: reports, redacted diagnostics |
| `WG_STATE_DIR` | `/run/wg-harness` | root-only state: private keys, rendered configs |
| `WG_SKIP_INSTALL=1` | unset | skip `apt-get`, report installation checks as UNTESTED |
| `WG_DEBUG=1` | unset | verbose harness logging (still key-scrubbed) |

### Run one stage in isolation

```bash
sudo bash scripts/00-preflight.sh        # platform capability snapshot
sudo bash scripts/02-keygen.sh           # key generation into /run/wg-harness (mode 0700)
sudo bash scripts/04-tunnel-up.sh        # namespaces + interfaces
sudo bash scripts/05-handshake.sh        # wait for a real handshake, print counters
```

Stages 03 and later assume the earlier stages have run; they fail closed with an
explicit message rather than guessing.

---

## What is checked

The full check list with IDs is in [`docs/TEST-REPORT.md`](docs/TEST-REPORT.md). The
task's ten required test areas map onto it like this:

| # | Required test | Checks |
|---|---|---|
| 1 | Dependency installation | `DEP-00..03`, `PRE-01` |
| 2 | Kernel and networking capabilities | `PRE-02..04`, `TUN-01..06` |
| 3 | WireGuard configuration validity | `CFG-01..08` (validated *before* any service starts) |
| 4 | Key generation and secure storage | `KEY-01..06` |
| 5 | Endpoint reachability | `PRE-05`, `PRE-06`, `TUN-05`, `REC-03` |
| 6 | Handshake establishment | `HS-01..04` |
| 7 | DNS and routing behaviour | `RT-01..04`, `DNS-01..03` |
| 8 | Client connectivity | `CON-01..05` |
| 9 | Failure recovery | `REC-01..04` |
| 10 | Resource cleanup | `CLN-01..04`, `SEC-01..05` |

Three design rules make those numbers mean something:

1. **A check passes only on an observation.** `HS-01` passes only when a non-zero
   `latest-handshakes` value is read back from the kernel. `CON-04` passes only when
   an HTTPS body fetched from the client namespace arrives *through* `wg0`. A step
   exiting `0` is not evidence.
2. **Not-run is a first-class result.** `UNTESTED` and `SKIP` are recorded,
   reported and never counted as passes. A missing `iptables` produces `UNTESTED`,
   not a green check.
3. **Every claim is reproducible.** Each check records the command's output,
   count and timestamp in `artifacts/checks.ndjson`.

---

## Repository layout

```
.github/workflows/
  wireguard-validation.yml      matrix harness run; publishes report + annotations
  wireguard-static-analysis.yml ShellCheck, Python AST/compile, yamllint, unit tests
scripts/
  00-preflight.sh               platform capability snapshot (PRE-*)
  01-install.sh                 dependency installation (DEP-*)
  02-keygen.sh                  key generation, mode 0600 (KEY-*)
  03-config-validate.sh         render + structurally validate configs (CFG-*)
  04-tunnel-up.sh               namespaces, interfaces, NAT, DNS responder (TUN-*)
  05-handshake.sh               handshake + transfer counters (HS-*)
  06-routing-dns.sh             routing table decisions, tunnel DNS (RT-*, DNS-*)
  07-connectivity.sh            ICMP/UDP/TCP/egress/MTU (CON-*)
  08-recovery.sh                failure injection and recovery (REC-*)
  09-cleanup.sh                 teardown + verification (CLN-*)
  10-leak-audit.sh              secret scan over every publishable surface (SEC-*)
  11-diagnose.sh                standalone triage for a live host
  report.sh                     NDJSON -> test-report.json + test-report.md + step summary
  run-suite.sh                  orchestrator (dependency order, traps, exit status)
  render-config.sh              template -> config, refuses unresolved placeholders
  validate_config.py            structural validator (unknown keys, overlaps, MTU)
  secret_scan.py                two-pass secret scanner with provenance mode
  dns_test_server.py            authoritative + forwarding DNS responder
  dns_query.py                  dependency-free DNS client
  lib/common.sh                 shared helpers: logging, retries, redaction, checks
tests/                          local unit tests and workflow policy tests
examples/                       server + client configuration templates (placeholders only)
docs/                           feasibility, architecture, security, test report, troubleshooting
```

---

## Deployment (the part Actions cannot do)

The harness proves the configuration is correct; it does not give you an endpoint.
To get a working VPN, put the server on a host you are authorised to use — a VPS, a
home router, a small ARM box — and let this repository's config renderer and
diagnostics handle the rest.

```bash
# 1. On the server: generate keys, render and validate a server config.
sudo bash scripts/02-keygen.sh
sudo bash scripts/03-config-validate.sh

# 2. Fill in examples/values.json (see docs/CONFIGURATION.md), then render.
scripts/render-config.sh --values examples/values.json --out-dir /etc/wireguard

# 3. Bring it up and verify, using the same checks the CI harness uses.
sudo wg-quick up wg0
sudo bash scripts/11-diagnose.sh          # handshake, routing, DNS, leak scan
```

Full instructions, including the client configuration and how to tell a *working*
config from a *template that still needs your values*, are in
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md). The client configuration produced for
you is a template with placeholders — deliberately, because the endpoint address and
the keys can only be filled in by you on a host you control.

---

## Security posture

* Private keys, preshared keys and rendered configurations live in `WG_STATE_DIR`
  (`/run/wg-harness`, mode `0700`) and are **never** written into the repository,
  the artifact tree, the job summary or any log. Diagnostics go through a redactor
  first, and `SEC-01..05` verify that afterwards by scanning every publishable
  surface — including with a provenance pass that knows the exact key values.
* Configurations are structurally validated *before* `wg-quick` sees them, so a
  malformed file cannot half-start a tunnel.
* Every failure path is bounded: `wg_retry`/`wg_wait_for` have attempt caps and
  timeouts, and no loop is unbounded.
* Workflows run with `permissions: contents: read`, third-party Actions pinned to
  verified commit SHAs, `persist-credentials: false`, and per-job timeouts.

Threat model, assets, trust boundaries and residual risks: [`docs/SECURITY.md`](docs/SECURITY.md).

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/FEASIBILITY.md`](docs/FEASIBILITY.md) | What runners can and cannot do; policy analysis; architecture options A–E with a recommendation |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Mermaid diagrams: harness topology, data path, deployment, threat boundaries |
| [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) | Placeholder index and the meaning of every address/routing/DNS field |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Turnkey server + client setup, and which values only you can fill in |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Threat model, key handling, secret-scanning design, residual risks |
| [`docs/TEST-REPORT.md`](docs/TEST-REPORT.md) | Actual results with timestamps, and every UNTESTED case with its reason |
| [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | Symptom → cause → fix, plus how to capture a good bug report |
| [`docs/CLEANUP.md`](docs/CLEANUP.md) | Teardown, verification, and the recovery procedure if a run is interrupted |

## Licence and third-party notices

This repository contains no third-party code. Workflows reference
`actions/checkout` and `actions/upload-artifact` by commit SHA; the resolved versions
and their provenance are recorded in [`docs/SECURITY.md`](docs/SECURITY.md).
