# Cleanup and recovery

Two audiences read this document:

* **Harness runs** — cleanup is automatic and verified, but you should know what it
  removes and how to check.
* **Real deployments** — a host you own accumulates state that outlives a test run:
  interfaces, firewall rules, keys, and possibly a stray resolver override. Removing
  a WireGuard server properly is not just `wg-quick down`.

---

## 1. What the harness creates, and what removes it

| Artefact | Created by | Removed by | Verified by |
|---|---|---|---|
| netns `wgsrv`, `wgcli`, `wgctl` | `04-tunnel-up.sh` | `09-cleanup.sh` | `CLN-01` |
| `br-wg` bridge, `vethsrv`/`vethcli` pairs | `04-tunnel-up.sh` | deleting the namespaces removes the veths | `CLN-02` |
| `wg0` in each namespace | `04-tunnel-up.sh` | namespace deletion | `CLN-02` |
| MASQUERADE + FORWARD rules (root and netns) | `wg_setup_nat` | `09-cleanup.sh`, removed by **exact match** | `CLN-02` |
| Test DNS resolver, UDP echo, HTTP server | `04`, `07` | killed by process group on namespace removal | `CLN-04` |
| `WG_STATE_DIR` (`/run/wg-harness`) with all keys | `02-keygen.sh` | `09-cleanup.sh` | `CLN-03` |
| `artifacts/` | every step | **deliberately kept** — it is the evidence | `SEC-01..03` |

Cleanup runs from an `EXIT` trap in `run-suite.sh`, so it fires on a normal finish, on
a failing step, and on `SIGTERM` from a CI job timeout. `SIGINT`/`SIGTERM` are trapped
so the interruption is logged before teardown starts.

Verify a run left nothing behind:

```bash
ip netns list | grep -E 'wgsrv|wgcli|wgctl'     # expect no output
ip link show br-wg 2>&1                          # expect "does not exist"
sudo iptables -t nat -S POSTROUTING | grep MASQUERADE   # expect no rule for 192.168.77.0/29
sudo ls /run/wg-harness 2>&1                     # expect "No such file or directory"
pgrep -af 'dns_test_server|http.server|udp_echo' # expect no output
```

That is exactly what `CLN-01..04` automate; running the commands by hand is only
necessary if the suite itself was killed with `SIGKILL` (which no trap can catch) or
the machine lost power.

## 2. Manual recovery after a hard kill

Run these in order. Each is idempotent and each tolerates "already gone".

```bash
# 1. Namespaces first - this also removes the veth pairs and the interfaces inside.
sudo ip netns del wgsrv 2>/dev/null || true
sudo ip netns del wgcli 2>/dev/null || true
sudo ip netns del wgctl 2>/dev/null || true

# 2. The bridge, if it outlived its namespace.
sudo ip link del br-wg 2>/dev/null || true

# 3. Firewall rules. Delete by exact match, never by flushing the table -
#    a flush would also drop rules this project never created.
sudo iptables -t nat -D POSTROUTING -s 192.168.77.0/29 -o <wan-iface> -j MASQUERADE 2>/dev/null || true
sudo iptables -D FORWARD -i br-wg -o <wan-iface> -j ACCEPT 2>/dev/null || true
sudo iptables -D FORWARD -i <wan-iface> -o br-wg -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

# 4. Key material and rendered configs.
sudo rm -rf /run/wg-harness

# 5. Orphaned test servers, if a namespace deletion did not reap them.
sudo pkill -f 'dns_test_server.py' 2>/dev/null || true
sudo pkill -f 'udp_echo.py' 2>/dev/null || true

# 6. Anything root-owned under artifacts/ blocks a plain rm.
sudo chown -R "$(id -u):$(id -g)" artifacts 2>/dev/null || true
rm -rf artifacts
```

`<wan-iface>` is what `ip route get 1.1.1.1` reports as `dev`.

Then confirm with the verification block in §1.

> **If `/run/wg-harness` held keys that were ever real**, treat them as compromised
> the moment the host was interrupted mid-run: rotate them. On a deployment host that
> means generating a new keypair and re-issuing every client config, because
> regenerating only the server key breaks every client.

## 3. Leaving no trace in CI

Nothing to do. The runner VM is destroyed at the end of the job, taking namespaces,
keys and firewall rules with it. The two things that survive are the uploaded
artifact (intentionally public evidence, verified clean by `SEC-02`) and the job log
(scrubbed on the way in, verified by `SEC-01..03`).

## 4. Cleanly removing a real deployment

```bash
# 1. Take the interface down (flushes routes wg-quick added, and its own nft/iptables rules).
sudo wg-quick down wg0

# 2. Remove persistence.
sudo rm -f /etc/wireguard/wg0.conf                  # contains the server private key
sudo systemctl disable --now wg-quick@wg0 2>/dev/null || true

# 3. Remove forwarding/NAT that wg-quick's PostUp added automatically.
sudo sysctl -w net.ipv4.ip_forward=0                # only if nothing else needs it
sudo iptables -t nat -D POSTROUTING -o <wan-iface> -j MASQUERADE 2>/dev/null || true
sudo iptables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true
sudo iptables -D FORWARD -o wg0 -j ACCEPT 2>/dev/null || true
# nftables equivalent:
# sudo nft delete table inet wg-quick-wg0

# 4. Remove the DNS override, if you configured a resolver through the tunnel.
sudo resolvectl revert wg0 2>/dev/null || true

# 5. Revoke every client, not just the server.
#    Simplest correct answer: delete the keys and re-issue. Removing one [Peer]
#    block revokes exactly one client and is safe to do live:
sudo wg set wg0 peer <CLIENT_PUBLIC_KEY> remove
```

Revocation is per-peer and live: `wg set wg0 peer <pub> remove` takes effect
immediately, without touching other clients. Deleting the whole interface is the
blunt version and logs everyone out.

### Rotating a compromised key without downtime

```bash
# On the server:
sudo wg genkey > /etc/wireguard/new-server.key && chmod 600 /etc/wireguard/new-server.key
sudo wg pubkey < /etc/wireguard/new-server.key          # distribute this to clients
# Add the new key alongside the old one, move clients over, then remove the old:
sudo wg set wg0 private-key /etc/wireguard/new-server.key
```

Clients keep working if they accept either public key during the overlap; WireGuard
has no key-list mechanism, so "overlap" in practice means updating the `[Peer]`
`PublicKey` on each client while the old session is still alive. Plan a window.

## 5. Uninstalling the harness from a workstation

```bash
sudo rm -rf /run/wg-harness
sudo rm -rf artifacts
# Optional, if the tools were installed only for this harness:
sudo apt-get remove --purge wireguard-tools
```

Nothing was installed into the repository working tree, and no system configuration
file was modified outside `/run/wg-harness` and the testbed's namespaces.
