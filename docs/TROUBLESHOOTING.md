# Troubleshooting

Symptom-first. Each entry gives the likely cause, how to confirm it, and the fix.
Check IDs refer to [`TEST-REPORT.md`](TEST-REPORT.md).

Before anything else, get a triage dump. It is read-only, safe to run on a live host,
and it redacts the key column before writing:

```bash
sudo bash scripts/11-diagnose.sh all
less artifacts/diagnostics/manual-triage.txt
```

---

## The harness exits non-zero

That is the design: the suite's exit status is derived from the recorded check rows,
so a non-zero exit always has at least one `FAIL` row. Find it in the report:

```bash
jq -r '.checks[] | select(.status != "PASS") | "\(.status)  \(.id)  \(.description) -- \(.detail)"' \
   artifacts/test-report.json
```

On a workflow run, the same list is on the commit's check run as annotations
(`Actions → the run → Annotations`), including a grouped evidence digest.

### `FAIL PRE-05` — "Outbound UDP/53 reachable"

**Cause:** the host cannot send UDP to a public resolver, or DNS egress is filtered.
This is an *environment* fact, not a WireGuard problem.

```bash
python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
q = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
s.sendto(q, ('1.1.1.1', 53)); print(len(s.recvfrom(512)[0]), 'bytes')
PY
```

**Fix:** allow outbound UDP/53, or accept that `DNS-03` and the upstream-forwarding
part of the DNS test will be `UNTESTED`. The tunnel itself does not need DNS egress;
only the test resolver's upstream forwarding does. Expect this check to fail in
sandboxes with a filtered egress policy — the two CI legs pass it.

### `FAIL PRE-03` — "Kernel WireGuard interface can be created"

**Cause:** no `wireguard` kernel module and no `wireguard-go` fallback.

```bash
modprobe wireguard 2>&1; ls /sys/module/wireguard 2>&1; uname -r
```

**Fix:** install `linux-modules-extra-$(uname -r)`, or use a kernel built with
`CONFIG_WIREGUARD=y`. Inside a container, the module must be loaded on the *host*;
`dkms` and a kernel newer than the userspace tools both matter. `wireguard-go` is a
valid fallback but the harness reports it distinctly, because a userspace data path
has different performance and MTU characteristics.

### `FAIL PRE-02` — "Passwordless root/sudo available"

**Cause:** the harness creates interfaces and namespaces; that needs `CAP_NET_ADMIN`
in the host network namespace.

**Fix:** run the suite with `sudo -E env … bash scripts/run-suite.sh`. Preserve the
environment with `-E`, otherwise `WG_ARTIFACT_DIR` and `WG_SKIP_INSTALL` are dropped
and the artifacts land somewhere unexpected.

### `UNTESTED TUN-06` / `CON-04` — "iptables is not installed"

**Cause:** no netfilter userspace tool, so forwarding and NAT cannot be configured
and the internet-egress path cannot be exercised.

**Fix:** `apt-get install -y iptables` (or `nftables` plus its `iptables` shim). The
harness deliberately reports `UNTESTED` rather than passing or failing: the tunnel is
unaffected, but no claim is made about egress.

### `SKIP` rows

`SKIP` means a prerequisite step failed, so the dependent check was never attempted.
It is *not* a pass. Look for the earliest `FAIL`; that is the real problem.

---

## Handshake never completes

### `HS-01` times out with both interfaces up

Work in this order — each step rules out a whole class of cause.

```bash
# 1. Is the interface actually listening, and on the port you think?
sudo wg show            # "listening port" must equal the configured ListenPort

# 2. Can the client even reach the endpoint address?
sudo ip netns exec wgcli ping -c2 192.168.77.2
sudo ip netns exec wgcli ss -lunp        # expect an outbound socket, not a listener

# 3. Do the keys match? This is the most common cause, and it is silent.
sudo wg show wg0 public-key                                     # server side
sudo ip netns exec wgcli wg show wg0 peers                      # must equal the above
```

**Cause 1 — key mismatch.** WireGuard gives no error for a wrong public key; the
handshake simply never completes. Compare `public-key` on one side against the peer
entry on the other. `REC-04` and `REC-02` exist to make this diagnosable quickly.

**Cause 2 — wrong `Endpoint`.** The endpoint must name a *reachable* address and the
same UDP port as the peer's `ListenPort`. A hostname that resolves differently inside
a namespace than outside it is a classic trap.

**Cause 3 — preshared key mismatch.** This one *does* fail closed and is testable:
`REC-01` asserts that a wrong PSK produces no handshake at all. If `REC-01` passes
and `HS-01` fails, your PSK is not the problem.

**Cause 4 — an MTU or fragmentation issue on the path.** Send a large, DF-marked
probe (`sudo ping -M do -s 1392 …`) and see whether the handshake packets are the
ones being dropped.

### Handshake completes but `HS-03` shows zero transfer

The interfaces are up and DTLS-like negotiation succeeded, but no transport data
flowed. Usually `AllowedIPs` does not cover the address you are pinging — the packet
never enters the tunnel, so nothing is encrypted. Confirm with `RT-01`:

```bash
sudo ip netns exec wgcli ip route get 10.13.13.1     # must say "dev wg0"
```

---

## DNS does not resolve through the tunnel

`DNS-02` is the negative control: it asserts the same lookup **fails** when the
tunnel is down. If `DNS-01` passes and `DNS-02` also "passes" as a success, the test
is not measuring what it claims — treat that as a harness bug, not a win.

```bash
sudo ip netns exec wgcli cat /etc/resolv.conf     # the configured resolver
sudo ip netns exec wgcli python3 scripts/dns_query.py gateway.wg.internal 10.13.13.1
```

**Cause — resolver not reachable inside the tunnel.** The `DNS` value must be an
address that is only routable *through* `wg0`. Pointing it at a public resolver
proves nothing and usually fails inside a namespace with no other route.

**Cause — forwarding resolver has no upstream.** `DNS-03` is `UNTESTED` whenever the
test resolver cannot reach its own upstream (see `PRE-05`). That is an environment
limitation, not a tunnel failure.

---

## Works intermittently, or stops after a while

**Cause — NAT mapping expiry on the client side.** Without
`PersistentKeepalive = 25` a client behind NAT goes silent after ~2 minutes and the
server's session expires after ~180 s. `REC-04` explicitly tolerates session reuse
for this reason; do not "fix" it by requiring a fresh handshake.

**Cause — endpoint address changed.** If the server's public IP is dynamic, the
client keeps sending to a stale address (`REC-03` reproduces exactly that). Fix the
address, or use a DNS name with a short TTL, or a stable relay. There is no
client-side setting that survives an endpoint moving.

---

## The leak audit fails

`SEC-01`/`SEC-02`/`SEC-03` failing means key material reached a publishable surface.
This is the one failure you stop and fix before doing anything else.

```bash
python3 scripts/secret_scan.py . --exclude "$PWD/artifacts"      # working tree
python3 scripts/secret_scan.py artifacts                         # what would be uploaded
python3 scripts/secret_scan.py . --secrets-from /run/wg-harness/keys   # provenance pass
```

The scanner prints one `LEAK <path>:<line> token=<first8>…` line per hit. Then:

1. Rotate the key. Assume anything that reached a log or an artifact is compromised —
   it is cheap to regenerate (`wg genkey`, `wg genpsk`) and expensive to be wrong.
2. Fix the producer, not just the file. A redacted file that keeps being regenerated
   is not a fix.
3. Re-run `sudo bash scripts/10-leak-audit.sh`.

If the scanner reports a *public* key, check the label: it recognises
`PublicKey =`, `public_key =`, `  public key:` and `peer: <key>`. Anything else is
treated as suspicious on purpose. Widen the recogniser only with a test that proves
the new shape cannot also hold a secret.

---

## A run was interrupted (Ctrl-C, timeout, killed job)

Interfaces, namespaces or keys may be left behind. See
[`CLEANUP.md`](CLEANUP.md) — it has the verification commands and the manual
recovery procedure.

---

## Filing a good bug report

Include:

* the check ID and its `detail` string from `artifacts/test-report.json`;
* `artifacts/runner-facts.txt` or `uname -a` plus the distro release;
* the relevant `artifacts/logs/STEP-<id>.log` (these are already key-scrubbed);
* `artifacts/diagnostics/manual-triage.txt` if you ran `11-diagnose.sh`.

Never include a private key, a rendered configuration, or anything from
`WG_STATE_DIR`. If you are unsure whether a file is safe, run
`python3 scripts/secret_scan.py <file>` first.
