# Deployment and client configuration

This is the path that produces a **working VPN**. The CI harness proves the
configuration is correct; this document turns it into a live endpoint on a host you
are authorised to administer.

> **Read this first.** Everything the renderer produces from the templates in this
> repository is a **template with placeholders** until *you* supply four values that
> only you can know: the server's public endpoint address, the server's key material,
> your client's private key, and the tunnel addresses you have chosen. A file that
> still contains placeholders is **not** a working configuration, and the validator
> will refuse it unless you explicitly pass `--allow-placeholders`.

---

## 1. Prerequisites

| Requirement | Why |
|---|---|
| A host with a stable, publicly reachable address | A WireGuard server is useless if clients cannot find it. Dynamic address → use DNS with a short TTL |
| Root (or `CAP_NET_ADMIN`) on that host | Creating `wg0`, adding routes, enabling forwarding |
| UDP port forwarded/allowed on that port | WireGuard is UDP only; there is no TCP fallback |
| A Linux kernel with WireGuard (4.20+ in-tree) or `wireguard-go` | `scripts/00-preflight.sh` tells you which you have |
| The client: an *authorised* WireGuard client | Official apps, or any compatible implementation |

Before you change anything on the host, take the platform snapshot:

```bash
git clone https://github.com/asomethinggood-sys/Sssuwuyrjs && cd Sssuwuyrjs
sudo bash scripts/00-preflight.sh
jq . artifacts/preflight.json
```

`PRE-03` (interface creatable) and `PRE-06` (inbound reachability) are the two that
decide whether this host can be a server at all.

## 2. Server: keys and configuration

```bash
# 1. Generate keys and a PSK into a root-only directory (mode 0700, files 0600).
sudo bash scripts/02-keygen.sh
sudo ls -l /run/wg-harness/keys

# 2. Collect the values that only you can supply.
cat > /root/values.json <<'JSON'
{
  "SERVER_PRIVATE_KEY": "<contents of /run/wg-harness/keys/server.key>",
  "CLIENT_PUBLIC_KEY":  "<output of: wg pubkey < client.key, on the CLIENT>",
  "PRESHARED_KEY":      "<contents of /run/wg-harness/keys/preshared.key>",
  "SERVER_TUNNEL_IP":   "10.13.13.1",
  "CLIENT_TUNNEL_IP":   "10.13.13.2",
  "TUNNEL_CIDR":        "24",
  "TUNNEL_DNS":         "10.13.13.1",
  "TUNNEL_MTU":         "1420",
  "SERVER_LISTEN_PORT": "51820",
  "WAN_INTERFACE":      "eth0",
  "IPV6_FORWARDING":    "0"
}
JSON
chmod 600 /root/values.json

# 3. Render. Unresolved placeholders abort with the names of what is missing.
scripts/render-config.sh \
  --template examples/server.conf.template \
  --values /root/values.json \
  --out /etc/wireguard/wg0.conf \
  --redact /root/wg0.conf.redacted

# 4. Validate BEFORE starting anything.
python3 scripts/validate_config.py /etc/wireguard/wg0.conf

# 5. Start and verify with the same checks CI runs.
sudo systemctl enable --now wg-quick@wg0
sudo wg show
sudo bash scripts/11-diagnose.sh interfaces
```

`WAN_INTERFACE` is what `ip route get 1.1.1.1` reports as `dev`. The rendered
`PostUp`/`PostDown` lines add forwarding and a MASQUERADE rule for the tunnel subnet;
if your firewall is managed by something else, remove those lines from the template
copy you render and configure the rules in your own tooling.

## 3. Client configuration

### 3.1 Generate the client's own key first

**On the client**, not on the server, and never transmit the private half:

```bash
wg genkey | tee client.key | wg pubkey > client.pub
chmod 600 client.key
```

Only `client.pub` goes to the server (it fills `CLIENT_PUBLIC_KEY` above). The server
never needs, and must never receive, `client.key`.

### 3.2 Render the client config

```bash
cat > /root/client-values.json <<'JSON'
{
  "CLIENT_PRIVATE_KEY": "<contents of client.key, on the CLIENT>",
  "CLIENT_TUNNEL_IP":   "10.13.13.2",
  "TUNNEL_DNS":         "10.13.13.1",
  "TUNNEL_MTU":         "1420",
  "SERVER_PUBLIC_KEY":  "<output of: wg pubkey < server.key, on the SERVER>",
  "PRESHARED_KEY":      "<the same PSK the server uses>",
  "SERVER_ENDPOINT_HOST": "vpn.example.com",
  "SERVER_ENDPOINT_PORT": "51820",
  "CLIENT_ALLOWED_IPS":  "0.0.0.0/0",
  "CLIENT_PERSISTENT_KEEPALIVE": "25"
}
JSON
chmod 600 /root/client-values.json

scripts/render-config.sh \
  --template examples/client.conf.template \
  --values /root/client-values.json \
  --out /root/wg-client.conf
```

The rendered file contains a private key: it is a credential. Move it to the client
over a channel you trust, and delete the intermediate copy.

### 3.3 What each client field means

| Field | Meaning | How to choose |
|---|---|---|
| `Address` | The client's own address *inside* the tunnel. It is not related to the public address | A `/32` from your tunnel subnet. Must match the `AllowedIPs` entry for this client in the server config |
| `PrivateKey` | This client's identity. Generated on the client, never leaves it | `wg genkey` on the client |
| `DNS` | Resolver the client uses **while the tunnel is up** | An address reachable *through* the tunnel, normally the server's tunnel IP running a resolver |
| `MTU` | Largest packet the tunnel will carry | Default 1420 (1500 minus WireGuard's ~60-byte overhead). Lower it to 1380 or so if you see large-packet stalls behind a PPPoE or double-NAT link |
| `PublicKey` (peer) | The server's public key | `wg pubkey < /etc/wireguard/wg0.key` on the server |
| `PresharedKey` (peer) | Extra symmetric key mixed into the handshake; post-quantum hardening | `wg genpsk`. Must be **identical on both ends**. A mismatch fails closed — no handshake, no traffic, no error message |
| `Endpoint` | Where the server is: `host:port` | The server's stable public address and its `ListenPort`. Never a GitHub runner's address — see below |
| `AllowedIPs` (peer) | **Which destinations go into the tunnel.** This is a routing decision, not an ACL | `0.0.0.0/0` = full tunnel. The server's tunnel subnet only = split tunnel. An address not listed here is routed *outside* the tunnel, not blocked |
| `PersistentKeepalive` | Seconds between keepalives | `25` if the client is behind NAT and must stay reachable; `0` otherwise. It keeps the client's NAT mapping open — it does **not** fix an unreachable server |

### 3.4 Importing on an authorised client

| Platform | Steps |
|---|---|
| Linux (NetworkManager) | `nmcli connection import type wireguard file wg-client.conf` |
| Linux (wg-quick) | copy to `/etc/wireguard/wg0.conf`, then `sudo wg-quick up wg0` |
| Android / iOS | official WireGuard app → **Add tunnel** → **Import from file or archive** → select the `.conf` |
| Windows / macOS | official WireGuard client → **Import tunnel(s) from file** → select the `.conf` |

Then verify from the client:

```bash
sudo wg show                      # expect a recent handshake and non-zero transfer
ip route get 10.13.13.1           # expect "dev wg0"
curl -sS https://example.com      # full tunnel: must succeed through the tunnel
```

## 4. Working configuration vs. template — how to tell

| | Template (in this repo) | Working configuration |
|---|---|---|
| `PrivateKey` value | `{{CLIENT_PRIVATE_KEY}}` or `<...>` | 44-character base64, ends in `=` |
| `Endpoint` | `{{SERVER_ENDPOINT_HOST}}:{{SERVER_ENDPOINT_PORT}}` or a documentation address | A real hostname or IP that answers on that UDP port |
| Validator | rejected unless `--allow-placeholders` is passed | accepted by `python3 scripts/validate_config.py` |
| Handshake | impossible | `wg show` reports `latest handshake: N seconds ago` |

If `wg show` says `latest handshake: (never)` and the transfer counters are all zero,
you have a template, a key mismatch, or a blocked UDP port — in that order of
likelihood. Follow [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md).

## 5. Why the endpoint can never be a GitHub runner

GitHub-hosted runners are ephemeral VMs behind provider NAT: no static public
address, no inbound reachability, and the VM is destroyed when the job ends. A client
config pointing at one would stop working within minutes and would be relying on
Actions as a hosted service, which the GitHub Terms for Additional Products and
Features exclude. [`FEASIBILITY.md`](FEASIBILITY.md) §2.2–2.4 shows the observation
and the policy text behind that statement. Use the runner to *test*, and a host you
control to *serve*.

## 6. Handover checklist

- [ ] `sudo bash scripts/00-preflight.sh` → `PRE-03` PASS, `PRE-06` documents the
      host's real inbound situation
- [ ] `scripts/render-config.sh` completes with no unresolved variables
- [ ] `python3 scripts/validate_config.py <conf>` exits 0 on both ends
- [ ] `wg-quick up` succeeds and `wg show` reports a handshake within 30 s
- [ ] `sudo bash scripts/11-diagnose.sh all` shows the expected route for the tunnel
      subnet and no key material
- [ ] The client config was transferred out of band and the intermediate copy deleted
- [ ] `python3 scripts/secret_scan.py .` is clean in any repository you keep configs in
- [ ] Rollback rehearsed: `docs/CLEANUP.md` §4
