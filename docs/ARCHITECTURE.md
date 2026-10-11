# Architecture

Two architectures live in this repository and they must not be confused:

1. **The validation harness** — what GitHub Actions runs on every commit. Hermetic,
   disposable, no inbound reachability, proves the data path works.
2. **The deployment kit** — what you run on a host you own. That is where a real
   WireGuard endpoint exists.

The harness exists because a hosted runner *cannot* be the second architecture.
[`FEASIBILITY.md`](FEASIBILITY.md) §2.2 proves that claim from GitHub's own
documentation and the runner's observed network behaviour.

---

## 1. Harness topology (one job, one runner, one kernel)

Everything below happens inside a single throwaway VM. The runner's real network is
touched only for DNS/HTTPS egress tests.

```mermaid
flowchart TB
    subgraph Runner["GitHub-hosted runner (ephemeral Ubuntu VM, passwordless sudo)"]
        subgraph Root["root network namespace"]
            ETH["eth0 &mdash; provider NAT<br/>no inbound reachability"]
            BR["br-wg<br/>192.168.77.1/29"]
            NAT["iptables MASQUERADE<br/>+ ip_forward=1"]
        end

        subgraph SRV["netns wgsrv (the &quot;server&quot; role)"]
            V1["vethsrv<br/>192.168.77.2/29"]
            WG0["wg0 &mdash; kernel WireGuard<br/>10.13.13.1/24 &middot; UDP 51820"]
            DNS["dns_test_server.py<br/>10.13.13.1:53<br/>authoritative + forwarding"]
            HTTP["http.server :8080<br/>UDP echo :9999"]
        end

        subgraph CLI["netns wgcli (the &quot;client&quot; role)"]
            V2["vethcli<br/>192.168.77.3/29"]
            WG1["wg0 &mdash; kernel WireGuard<br/>10.13.13.2/24 &middot; listen 51821"]
        end
    end

    ETH --- BR
    BR --- V1
    V1 --- WG0
    V2 --- WG1
    WG0 <-.->|"real UDP :51820<br/>Noise IK handshake<br/>ChaCha20-Poly1305"| WG1
    WG0 --- DNS
    WG0 --- HTTP
    BR --- NAT
    NAT -.->|"CON-04: HTTPS through the tunnel"| ETH
```

Why a `veth`/bridge between the namespaces instead of `127.0.0.1`? Because a
loopback peer would hide exactly the failures this harness exists to catch — MTU
miscalculation, `AllowedIPs` mistakes, source-address selection, and the routing
decision that decides whether a packet enters the tunnel at all. The veth gives the
two peers distinct addresses on a real link, so `RT-*` can assert *which* interface a
given destination is routed through.

Why put the "server" in its own namespace rather than on the root? So that the
harness can assert the client's traffic genuinely traverses `wg0` and the server's
NAT, and so cleanup is verifiable: if a namespace still exists, cleanup failed.

---

## 2. Data path of a single client request (`CON-03`)

```mermaid
sequenceDiagram
    participant C as wgcli namespace
    participant K1 as wg0 (client, kernel)
    participant K2 as wg0 (server, kernel)
    participant S as http.server in wgsrv

    C->>K1: curl http://10.13.13.1:8080/health.txt
    Note over C: routing table says 10.13.13.1 dev wg0<br/>(RT-01 asserts this)
    K1->>K1: allowed-ips match, ChaCha20-Poly1305 seal,<br/>outer header 192.168.77.3 -> 192.168.77.2:51820
    K1->>K2: UDP over veth (MTU 1420, DF bit set)
    K2->>K2: decrypt, verify, NAT/forward
    K2->>S: delivers plaintext 10.13.13.2 -> 10.13.13.1
    S-->>K2: HTTP 200 "ok"
    K2-->>K1: seal return packet
    K1-->>C: plaintext body
    Note over C,S: CON-03 passes only when the body equals "ok"
```

The first packet on a fresh interface triggers the handshake, so the observable
provenance of a working tunnel is the handshake counter:

```mermaid
sequenceDiagram
    participant K1 as client wg0
    participant K2 as server wg0

    K1->>K2: handshake initiation (Noise_IKpsk2, ephemeral Curve25519)
    K2->>K1: handshake response + first transport keys
    K1->>K2: keepalive / data (ChaCha20-Poly1305)
    Note over K1,K2: HS-01 reads latest-handshakes from the kernel on BOTH sides<br/>and requires the same non-zero timestamp
    Note over K1,K2: REC-01 proves fail-closed behaviour:<br/>a wrong preshared key yields NO handshake at all
```

---

## 3. Harness control flow

```mermaid
flowchart LR
    P["00 preflight<br/>PRE-01..06"] --> I["01 install<br/>DEP-00..03"]
    I --> K["02 keygen<br/>KEY-01..06"]
    K --> C["03 config render + validate<br/>CFG-01..07"]
    C --> T["04 tunnel up<br/>TUN-01..06"]
    T --> H["05 handshake<br/>HS-01..04"]
    H --> R["06 routing + DNS<br/>RT-*, DNS-*"]
    H --> N["07 connectivity<br/>CON-01..05"]
    H --> V["08 recovery<br/>REC-01..04"]
    R --> X["cleanup<br/>CLN-01..04"]
    N --> X
    V --> X
    X --> L["10 leak audit<br/>SEC-01..05"]
    L --> RP["report.sh<br/>test-report.{json,md}<br/>+ job summary"]
```

`run-suite.sh` enforces three properties:

* **dependency order** — a step whose prerequisite failed is recorded `SKIP`, never
  run against a half-built testbed;
* **cleanup on every path** — an `EXIT` trap tears the testbed down even on `SIGTERM`
  or a failing step, and `SIGINT`/`SIGTERM` are trapped to log the interruption;
* **honest exit status** — the suite's exit code is derived from the recorded check
  rows, not from the last command that happened to run.

---

## 4. Deployment architecture (a host you own)

```mermaid
flowchart LR
    subgraph Net["Client network"]
        L["Laptop / phone / router<br/>wg0 10.13.13.2/32"]
    end
    subgraph Internet["Internet"]
        EP["UDP :51820<br/>server public endpoint"]
    end
    subgraph Host["Authorised server host (VPS, home box, ARM board)"]
        subgraph Kernel["Linux kernel"]
            WS["wg0 &mdash; 10.13.13.1/24"]
            FW["nftables / iptables<br/>INPUT allow UDP 51820<br/>FORWARD + MASQUERADE"]
            DNSR["resolver (systemd-resolved<br/>or Unbound)"]
        end
    end

    L -->|"WireGuard UDP, encrypted"| EP
    EP --> WS
    WS --> FW
    FW -->|"NATed egress"| Internet
    L -.->|"DNS through the tunnel"| DNSR
```

The endpoint must be reachable at a **stable** address for the client config to be
worth distributing, which is precisely what an ephemeral runner cannot provide — a
`PersistentKeepalive` setting only helps a client behind NAT, it does nothing for a
server whose address changes on every run.

---

## 5. Trust boundaries

```mermaid
flowchart TB
    subgraph TB1["Boundary 1 - untrusted input"]
        CFG["config templates in git<br/>(placeholders only)"]
        PR["pull requests from forks"]
    end
    subgraph TB2["Boundary 2 - ephemeral, root"]
        RUN["harness steps in the VM<br/>root, but only inside it"]
        KEYS["WG_STATE_DIR<br/>/run/wg-harness mode 0700"]
    end
    subgraph TB3["Boundary 3 - publishable"]
        ART["artifacts/ (uploaded)"]
        SUM["job summary"]
        ANN["annotations"]
        LOG["job log"]
    end
    subgraph TB4["Boundary 4 - the internet"]
        OUT["outbound DNS/HTTPS<br/>egress only"]
    end

    PR -->|"no secrets, contents:read token,<br/>no pull_request_target"| RUN
    CFG -->|"rendered, never the reverse"| RUN
    RUN --> KEYS
    RUN -->|"redacted by wg_scrub and<br/>wg_redact_dump, then approved<br/>by secret_scan.py"| ART
    ART --> SUM
    ART --> ANN
    KEYS -.->|"never"| LOG
    RUN --> OUT
    KEYS -.->|"never"| OUT
```

The load-bearing rule is the dotted line: **key material never crosses from
boundary 2 to boundary 3.** It is enforced mechanically rather than by convention —
`wg_scrub` filters every log line, `wg_redact_dump` masks the private-key and
preshared-key columns of `wg show dump`, and `10-leak-audit.sh` then independently
scans the working tree, the artifact tree and the job summary with
`secret_scan.py --secrets-from`. See [`SECURITY.md`](SECURITY.md) for the failure
analysis.

---

## 6. Why the report is generated from NDJSON

`wg_check` appends one JSON object per check to `artifacts/checks.ndjson` as the run
proceeds. Reports are *derived* from that file rather than from the scripts
returning success:

* a step that dies halfway still leaves the checks it completed;
* the report can never claim more than was recorded;
* the same file feeds `test-report.json` (machine-readable), `test-report.md`
  (human), the job summary, and the annotation step.

```mermaid
flowchart LR
    S["harness scripts"] -->|"wg_check ID STATUS desc detail"| N["artifacts/checks.ndjson"]
    N --> J["test-report.json"]
    N --> M["test-report.md"]
    N --> G["$GITHUB_STEP_SUMMARY"]
    N --> A["check-run annotations<br/>(errors, warnings, evidence digest)"]
```
