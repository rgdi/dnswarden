# DNSWarden

> Ultra-lightweight DNS-over-HTTPS (DoH) server with Cloudflare Family filtering, proxy blocking, and aggressive caching. Python + CoreDNS.

## What it does

- **DoH proxy** listening on `:54321/tcp` — fully RFC 8484 compliant (GET + POST)
- **Upstream**: Cloudflare Family (`1.1.1.3` / `1.0.0.3`) — blocks malware and adult content automatically
- **Proxy blocker**: local `blacklist.txt` blocks 35+ known web proxy circumvention tools
- **Aggressive caching**: 7-day cache for positive answers, 1-hour for NXDOMAIN
- **Zero external dependencies** in the DoH layer — Python stdlib only
- **~25 MB total RAM** (CoreDNS ~12 MB + Python proxy ~8 MB)

## Quick Start

```bash
git clone https://github.com/rgdi/dnswarden.git
cd dnswarden

# Optional: edit Corefile to use your upstream if not using Cloudflare Family
$EDITOR Corefile

# Ensure nothing else is using port 53 on the host
# (systemd-resolved: edit /etc/systemd/resolved.conf → DNSStubListener=no)

docker compose up -d

# Verify
curl http://localhost:5054/health
# → OK
```

## Endpoints

| Endpoint | Protocol | Description |
|---|---|---|
| `http://localhost:54321/dns-query` | DoH GET/POST | RFC 8484 DNS-over-HTTPS |
| `http://localhost:5054/health` | HTTP GET | Health check |
| `tcp://localhost:5053` | DNS/TCP | Plain DNS fallback (no DoH) |
| `udp://127.0.0.1:53` | DNS/UDP | CoreDNS direct (host network) |

## Chromebook / Chrome Setup

1. Open `chrome://settings/security`
2. Scroll to **Advanced DNS settings**
3. Select **Custom DNS provider**
4. Enter your server's public IP or hostname: `https://your-server:54321/dns-query`

## Adding custom blocks

Edit `blacklist.txt`. Format:

```
0.0.0.0 proxy.example.com
0.0.0.0 vpn.example.net
```

Restart the CoreDNS container after editing:

```bash
docker compose restart coredns
```

## Architecture

```
                    ┌─────────────────────────────┐
Chromebook ──DoH──▶ │  doh-proxy.py (Python)       │
                    │  :54321/tcp  (RFC 8484)     │
                    │                             │
                    │         └── UDP ──▶ :53    │
                    │                             │
                    │  coredns/coredns:1.11.1    │
                    │  bind 127.0.0.1:53          │
                    │    ├── cache               │
                    │    ├── hosts (blacklist)   │
                    │    └── forward ──▶ 1.1.1.3 │
                    └─────────────────────────────┘
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `LISTEN_HOST` | `0.0.0.0` | Bind address |
| `LISTEN_PORT` | `54321` | DoH port |
| `COREDNS_HOST` | `127.0.0.1` | CoreDNS host |
| `COREDNS_PORT` | `53` | CoreDNS port |

## Resource usage

| Container | Memory | CPU shares |
|---|---|---|
| coredns | 64 MB max | 128 |
| doh-proxy | 32 MB max | 64 |

Total: **≤96 MB**, ~0.05 CPU cores at idle.

## Requirements

- Linux host (for `network_mode: host`)
- Docker + Docker Compose v2
- Port 53 available on the host (or rebind systemd-resolved)
- Outbound UDP/TCP to `1.1.1.3:53` and `1.0.0.3:53`

## Troubleshooting

**`curl: (52) Empty reply from server`**

CoreDNS is not running. Check:
```bash
docker compose logs coredns
docker compose up -d coredns
```

**NXDOMAIN for everything**

Check if outbound DNS to `1.1.1.3` is being blocked in your network. Try changing `forward . 8.8.8.8` temporarily in `Corefile` to confirm CoreDNS is resolving at all.

**Port 53 already in use**

systemd-resolved is occupying port 53. Fix:
```bash
sudoedit /etc/systemd/resolved.conf
# Add: DNSStubListener=no
sudo systemctl restart systemd-resolved
```

## Security notes

- DoH endpoint is unauthenticated — suitable for personal/internal network use behind a firewall or behind Cloudflare Tunnel
- The `blacklist.txt` blocks proxy circumvention but is not a substitute for a full secure network policy
- Run the container with `--read-only` and dropped capabilities for production hardening

## License

MIT