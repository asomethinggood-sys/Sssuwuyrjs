# Configuration reference

Every value in `examples/*.template` is a `{{PLACEHOLDER}}`. Nothing is
pre-filled, because a configuration is only correct for a specific, verified
server endpoint.

Render a template with:

```bash
./scripts/render-config.sh \
  --template examples/client.conf.template \
  --values   my-values.json \
  --out      wg0.conf \
  --mode     600
```

`render-config.sh` refuses to write an output file that still contains `{{…}}`
or `<PLACEHOLDER>` markers unless you pass `--allow-unresolved`. Values are read
from the JSON file, never from environment variables, so key material never
appears in `/proc/<pid>/environ`.

## Placeholder index

| Placeholder | Applies to | Meaning / how to obtain it |
|---|---|---|
| `SERVER_PRIVATE_KEY` | server | `wg genkey` **on the server**. Never leaves the server. |
| `SERVER_PUBLIC_KEY` | client | `wg pubkey < server.key` on the server; safe to publish. |
| `SERVER_LISTEN_PORT` | server | UDP port the server binds, e.g. `51820`. Must be forwarded/reachable. |
| `SERVER_TUNNEL_IP` | server | The server's own address inside the tunnel, e.g. `10.13.13.1`. |
| `SERVER_ENDPOINT_HOST` | client | Public DNS name or IP of the server as reachable from the client. |
| `SERVER_ENDPOINT_PORT` | client | Usually identical to `SERVER_LISTEN_PORT`. |
| `CLIENT_PRIVATE_KEY` | client | `wg genkey` **on the client device**. Never transmitted. |
| `CLIENT_PUBLIC_KEY` | server | `wg pubkey` of the client key; added to the server's `[Peer]`. |
| `CLIENT_TUNNEL_IP` | both | The client's tunnel address; the server restricts its `AllowedIPs` to `…/32`. |
| `CLIENT_NAME` | server | Free-text comment identifying the peer (used in `#` comments only). |
| `CLIENT_ALLOWED_IPS` | client | `0.0.0.0/0` for a full tunnel; the server subnet for split tunnel. |
| `CLIENT_PERSISTENT_KEEPALIVE` | client | `25` keeps NAT mappings open on mobile networks; `0` disables it. |
| `PRESHARED_KEY` | both | `wg genpsk`; identical on both ends; adds a symmetric layer on top of the Noise handshake. |
| `TUNNEL_CIDR` | server | Prefix length of the tunnel subnet, e.g. `24`. |
| `TUNNEL_DNS` | client | Resolver address reachable inside the tunnel, usually `SERVER_TUNNEL_IP`. |
| `TUNNEL_MTU` | both | `1420` on typical Ethernet/Wi-Fi; `1380` or lower behind PPPoE/DS-Lite. |
| `WAN_INTERFACE` | server | Outbound NIC on the server, from `ip route get 1.1.1.1`. |
| `IPV6_FORWARDING` | server | `1` to forward IPv6, `0` to keep IPv6 off the tunnel. |

## Address assignment

* The server owns `SERVER_TUNNEL_IP` and one `/32` route per peer.
* Each client gets exactly one address; two clients must never share one.
* The server's `AllowedIPs` for a peer is *that peer's* `/32`. It is not a
  subnet: WireGuard treats `AllowedIPs` as a cryptokey routing table, and a
  wider prefix lets peers impersonate each other.
* Overlap between a peer's `AllowedIPs` and the server's own tunnel address is
  rejected by `scripts/validate_config.py`.

## Routing

| Deployment | Client `AllowedIPs` | Effect |
|---|---|---|
| Full tunnel | `0.0.0.0/0` | All IPv4 traffic leaves through the server. Requires `PostUp` NAT on the server. |
| Split tunnel | `10.13.13.0/24` | Only tunnel-addressed traffic is encrypted. |
| Site-to-site | the remote LAN prefixes | Joins two networks; no NAT needed if routes are added. |

With a full tunnel, `wg-quick` installs `0.0.0.0/1` and `128.0.0.0/1` so the
existing default route survives and can be restored cleanly. It also pins a
`/32` route to the endpoint so encapsulated packets do not re-enter the tunnel.
The harness asserts both behaviours in checks `RT-03` and `RT-04`.

## DNS

`DNS = …` in `[Interface]` is consumed by `wg-quick`, not by the WireGuard
protocol: `wg-quick` rewrites `/etc/resolv.conf` via `resolvconf`/`systemd-resolved`
and restores it on `down`. If you run `wg set` directly (as the CI harness
does), you must configure DNS yourself. The harness therefore writes
`/etc/netns/<ns>/resolv.conf` and proves that a resolver reachable *only*
through the tunnel answers queries.

Choose a resolver that is reachable inside the tunnel and that you trust; by
default this repository suggests the server's tunnel address with a resolver
bound to it.

## Required client-specific settings

* `PrivateKey` — unique per device. Never reuse a key across devices.
* `Address` — unique per device, `/32`.
* `PresharedKey` — optional but recommended; must match the server.
* `MTU` — must not exceed the server's MTU; lower it if large transfers stall.
* `PersistentKeepalive = 25` — needed behind NAT; unnecessary on a public client.

## What is *not* in a configuration file

WireGuard configuration files carry no usernames, passwords, or certificates.
The private key *is* the credential. Consequently:

* keep the file at mode `0600`;
* never commit it, never paste it into an issue, never email it;
* treat the `.conf` you import into a mobile client as a secret store item.
