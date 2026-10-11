# Feasibility report: WireGuard on GitHub-hosted runners

**Status:** verified against live platform behaviour and current official
documentation on 2026-10-11. Every claim below is labelled **VERIFIED**,
**DERIVED** (follows logically from a verified fact) or **ASSUMPTION**
(not yet measured — treat as unknown).

---

## 1. Executive summary

**A GitHub-hosted runner can speak WireGuard. It can never be the server half of
a VPN.**

Those are two different questions and conflating them is the usual error.

| Question | Answer | Evidence |
|---|---|---|
| Can a runner create a WireGuard interface? | **Yes, VERIFIED** | `PRE-03` passes on `ubuntu-22.04` and `ubuntu-24.04`; the kernel module is present and `iwl`-style interface creation succeeds under `sudo`. |
| Can a runner complete a real WireGuard handshake? | **Yes, VERIFIED** | `HS-01`–`HS-04` pass: the kernel reports a non-zero `latest-handshakes` value and non-zero rx/tx counters on both peers. |
| Can an external client reach a WireGuard listener on a runner? | **No, VERIFIED** | Standard runners have no inbound reachability and no static public IP. `PRE-06` records this; GitHub documents static IPs only for *larger runners* on paid plans. |
| Can a runner host a persistent VPN service? | **No — and it must not be attempted** | The VM is destroyed at job end (6-hour job ceiling), and hosting a standalone service on Actions breaches the Terms for Additional Products and Features. |
| Can the harness test routing, DNS, MTU and recovery without privileges we lack? | **Yes, VERIFIED** | Namespaces, `iptables`, `wg`, `ip rule` and DNS all work under the passwordless `sudo` the runner provides. |

**Recommendation:** use GitHub Actions as a *test harness* (this repository) and
run the production server on a host you are authorised to operate.

---

## 2. What was verified, and how

### 2.1 Platform facts

| Fact | Value | Source |
|---|---|---|
| Runner VM | 4 vCPU / 16 GB / 14 GB SSD, x64 (public repos) | GitHub docs, *GitHub-hosted runners reference* |
| Runner OS image | `ubuntu-24.04` → Ubuntu 24.04.5 LTS, kernel `6.17.0-1022-azure` | `actions/runner-images` Ubuntu2404-Readme |
| Administrative privileges | "The Linux and macOS virtual machines both run using passwordless `sudo`" | GitHub docs |
| Job execution ceiling | **6 hours** per job (GitHub-hosted); workflow run 35 days | GitHub docs, *Actions limits* |
| Static public IPs | Not available on standard runners; *larger runners* only, on Team/Enterprise | GitHub docs |
| Hosting location | Azure datacentre address space, shared, rotating weekly | GitHub docs; `/meta` API |

### 2.2 Network reality: outbound yes, inbound no

* **Outbound** connectivity works: package installs, HTTPS API calls and UDP/53
  to public resolvers all succeed from the runner (`PRE-05`, `DNS-03`).
* **Inbound** connectivity does not exist for standard runners. They sit behind
  provider NAT; the address changes per job and per run. Any WireGuard peer
  configured with `Endpoint = <runner>` fails, and the failure mode is a silent
  black hole rather than an error, because UDP has no connection refusal.
* **Endpoint stability**: there is none. A new job is a new VM with a new
  address. Nothing carries over: no keys, no interface state, no session keys.

### 2.3 Why "two simultaneous workflows" is not a service

Three specific mechanisms, each independently sufficient to break the idea:

1. **Separate VMs.** Concurrent jobs run on different hosts. They share no
   network namespace, no kernel, no routing table.
2. **No inbound path between them.** Runner-to-runner connections cannot be
   established because neither side accepts inbound traffic.
3. **No state transfer.** Keys, interfaces and sessions live in the VM and die
   with it. There is no supported channel to hand a live session to a later job.

A workflow can therefore *demonstrate* a tunnel (which this repository does,
inside one job, between two network namespaces) but cannot *provide* one.

### 2.4 Policy position

The GitHub Terms for Additional Products and Features state that Actions should
not be used for:

> "any other activity unrelated to the production, testing, deployment, or
> publication of the software project associated with the repository where
> GitHub Actions are used" — unless using self-hosted runners.

Operating a general-purpose VPN endpoint from a runner is unrelated to
producing, testing, deploying or publishing software, so it is out of scope.
It is also unavailable to GitHub Support to sanction: the platform cannot offer
a stable endpoint on standard runners.

This project therefore uses Actions strictly for what it is designed for:
building, testing and publishing. Nothing in this repository starts a
long-lived service, retries forever, or tries to work around a platform control.

### 2.5 What the harness actually builds

Because inbound reachability is impossible, the harness creates the two tunnel
endpoints *inside one job* in separate network namespaces joined by a veth/bridge
transport:

```
root netns (runner)
  br-wg 192.168.77.1/29
    ├── vethsrv ──> netns wgsrv : wg0 10.13.13.1/24  (server role), UDP/51820
    └── vethcli ──> netns wgcli : wg0 10.13.13.2/24  (client role)
```

This is a genuine WireGuard tunnel: kernel crypto, real UDP encapsulation, real
routing, real netfilter. What it does *not* prove is anything about an
internet-facing endpoint, because that is not testable from a runner. Checks
that cannot be performed are reported `UNTESTED`, never as passes.

---

## 3. Architecture options considered

### Option A — GitHub-hosted runner as the server

* Inbound reachability: **none**. Endpoint changes every job.
* Lifetime: at most 6 hours, typically minutes.
* Policy: breaches the Actions terms.
* Verdict: **not feasible, and not permitted.** Rejected.

### Option B — Two workflows cooperating (client workflow + server workflow)

* Both halves are separate VMs; neither can accept inbound traffic.
* No shared state channel exists for keys or sessions.
* Verdict: **not feasible.** Rejected. This is the "two simultaneous workflows"
  trap the brief warned about, and the platform behaviour above is the reason.

### Option C — Self-hosted runner as the server

* A self-hosted runner *can* accept inbound traffic and has a stable address.
* But it is no longer a GitHub-hosted service; it is your own machine. Using
  Actions to drive it adds a control plane, not reachability.
* Verdict: **feasible**, but the correct description is "a normal WireGuard
  server that happens to be managed by Actions". Choose it only if you already
  need the runner for other CI work.

### Option D — Authorised persistent host + Actions as the test harness ✅

* Server on a host you own or rent and are permitted to configure (VPS, home
  server, cloud instance, or a router that terminates WireGuard natively).
* Actions runs the full validation suite on every change, on real kernels.
* Cost: the VPS cost only; Actions minutes for public repositories are free.
* Verdict: **recommended.** This is what the repository is built around.

### Option E — Managed WireGuard provider

* If the operational burden of a persistent host is unacceptable, a hosted
  WireGuard/Tailscale-style provider gives a stable endpoint without you
  running a server. The same harness validates the client configuration and the
  rendered config can be pointed at any provider endpoint.
* Verdict: **feasible and often the cheapest to operate**, at the cost of
  trusting a third party with the endpoint.

---

## 4. Recommended architecture

```
┌────────────────────┐                    ┌──────────────────────────────┐
│ Client device      │  UDP/51820 (out)   │ Persistent host (yours)      │
│ (laptop/phone)     │ ─────────────────► │ wg0 10.13.13.1/24            │
│ wg0 10.13.13.2/32  │ ◄───────────────── │ NAT + forwarding for clients │
└────────────────────┘   encrypted        └──────────────────────────────┘
          ▲                                            ▲
          │ rendered from examples/client.conf.template│ config generated by
          │                                           │ scripts/render-config.sh
          └───────────────┐              ┌────────────┘
                          │              │
                 ┌────────┴──────────────┴─────────┐
                 │ GitHub Actions (test harness)   │
                 │ preflight → keys → config →     │
                 │ tunnel → handshake → routing →  │
                 │ DNS → connectivity → recovery → │
                 │ cleanup → leak audit → report   │
                 └─────────────────────────────────┘
```

**Trade-offs accepted:** the production endpoint is not validated by CI, because
CI cannot reach it. The harness validates everything that *is* reproducible —
key handling, config rendering, crypto handshake, routing, DNS, MTU, recovery —
and the client configuration is delivered with explicit placeholders for the
values only you can supply.

---

## 5. Limitations you must plan around

| # | Limitation | Impact | Mitigation in this repo |
|---|---|---|---|
| L1 | Runners have no inbound reachability | Cannot host an endpoint | Server lives on your host (`docs/ARCHITECTURE.md`) |
| L2 | 6-hour job ceiling | No long-lived service | Harness jobs finish in minutes; `timeout-minutes` cap per job |
| L3 | Ephemeral VMs | No state survives | All state generated per run and destroyed (`CLN-01`…`CLN-04`) |
| L4 | Actions terms restrict unrelated use | Hosting a VPN is out of policy | Nothing here runs as a service; documented above |
| L5 | Azure datacentre addresses are shared | Outbound reputation is inconsistent | Not relied upon |
| L6 | `ubuntu-22.04` is on a deprecation path | Matrix leg will need updating | Matrix is explicit rather than `-latest`; see `docs/TROUBLESHOOTING.md` |
| L7 | No CI access to the real endpoint | Production path untested by CI | Marked `UNTESTED`; manual checklist in `docs/TEST-REPORT.md` |

**Assumptions not verified** (stated so they are not mistaken for facts):
internet-path MTU for your specific ISP, your server provider's UDP handling,
and your client platforms' behaviour. These can only be confirmed on your own
hosts — the checklist in `docs/TROUBLESHOOTING.md` covers them.
