# traefik-pihole-sync

Automatically sync Traefik router hostnames to Pi-hole v6 local DNS records.

When services are added or removed behind Traefik, this script polls the Traefik API, extracts `Host()` rules, and pushes matching DNS entries to one or more Pi-hole v6 instances via the Pi-hole REST API.

## Features

- **Zero dependencies** — Python 3.6+ stdlib only
- **Pi-hole v6 REST API** — no SSH/SCP, no file manipulation
- **Multi-instance** — syncs to multiple Pi-hole instances with per-instance passwords
- **Change detection** — hashes the desired DNS set and skips Pi-hole API calls when nothing changed
- **Router filtering** — auto-excludes `@internal` routers, configurable blocklist
- **Backup & rollback** — snapshots Pi-hole DNS state before every sync, with manual rollback via `--rollback`
- **Dry run mode** — preview changes without applying
- **Structured logging** — clear summaries of what changed
- **Error handling** — retry with backoff, per-instance resilience, distinct exit codes, session cleanup
- **Conflict resolution** — detects and replaces existing DNS entries that point to the wrong IP

## How It Works

1. Fetches all HTTP routers from Traefik's API
2. Extracts hostnames from `Host()` rules, filtering out internal/blocklisted routers
3. Compares against a cached hash — exits early if nothing changed
4. Authenticates with each Pi-hole v6 instance
5. Backs up current DNS entries to a timestamped JSON file
6. Diffs desired vs. current entries (scoped to the Traefik IP) and applies adds/removes
7. Saves the cache hash on success

## Quick Start

```bash
# 1. Clone to your Traefik host
git clone https://github.com/jonmilele/traefik-pihole-sync.git /opt/traefik-dns-sync

# 2. Create .env with your settings
cat > /opt/traefik-dns-sync/.env << 'EOF'
TRAEFIK_IP="192.168.1.1"                                    # IP of your Traefik host
PIHOLE_HOSTS="192.168.1.2,192.168.1.3"                       # Comma-separated Pi-hole IPs
PIHOLE_PASSWORD_192_168_1_2="your-app-password-for-pihole-1"  # Per-instance app passwords
PIHOLE_PASSWORD_192_168_1_3="your-app-password-for-pihole-2"
EOF
chmod 600 /opt/traefik-dns-sync/.env

# 3. Test with a dry run
set -a && source /opt/traefik-dns-sync/.env && set +a
DRY_RUN=true DEBUG=1 python3 /opt/traefik-dns-sync/sync.py

# 4. Run for real
python3 /opt/traefik-dns-sync/sync.py

# 5a. Option A: Run as a systemd daemon (recommended)
sudo cp /opt/traefik-dns-sync/traefik-pihole-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now traefik-pihole-sync

# 5b. Option B: Run via cron (every 2 minutes)
(crontab -l 2>/dev/null; echo "*/2 * * * * /opt/traefik-dns-sync/sync.sh >> /var/log/traefik-dns-sync.log 2>&1") | crontab -
```

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|---|---|---|
| `TRAEFIK_URL` | `http://127.0.0.1:8080` | Traefik API base URL |
| `TRAEFIK_IP` | *(required)* | IP address of your Traefik instance |
| `PIHOLE_HOSTS` | *(required)* | Comma-separated Pi-hole IPs |
| `PIHOLE_PASSWORD` | *(none)* | Global Pi-hole app password |
| `PIHOLE_PASSWORD_<IP>` | *(none)* | Per-instance password (IP with dots replaced by underscores) |
| `PIHOLE_SCHEME` | `https` | `http` or `https` |
| `PIHOLE_PORT` | `443` | Pi-hole web port |
| `EXCLUDE_ROUTERS` | *(none)* | Comma-separated router names to skip |
| `EXCLUDE_PROVIDERS` | `internal` | Comma-separated providers to skip |
| `CACHE_FILE` | `/opt/traefik-dns-sync/.last_hash` | Path to hash cache file |
| `BACKUP_DIR` | `/opt/traefik-dns-sync/backups` | Path to backup directory |
| `BACKUP_RETAIN` | `10` | Backups to keep per Pi-hole host |
| `DRY_RUN` | `false` | Preview changes without applying |
| `DEBUG` | *(unset)* | Enable debug logging |
| `RETRY_ATTEMPTS` | `3` | Number of retry attempts for failed API requests |
| `RETRY_BACKOFF_BASE` | `2.0` | Base for exponential backoff (seconds) |
| `SYNC_INTERVAL` | `120` | Seconds between sync cycles in `--daemon` mode |

## Pi-hole Setup

1. **Generate an application password** in the Pi-hole web UI: Settings → API
2. **Enable app_sudo** so the app password can modify config:
   ```bash
   pihole-FTL --config webserver.api.app_sudo true
   ```

## Traefik Setup

The script needs access to the Traefik API. If running locally on the Traefik host, bind the API to localhost:

```yaml
entryPoints:
  traefik:
    address: '127.0.0.1:8080'

api:
  dashboard: true
  insecure: true
```

## Backup & Rollback

Backups are saved automatically before every sync to `/opt/traefik-dns-sync/backups/`.

```bash
# List backups
python3 sync.py --list-backups

# Preview a rollback
PIHOLE_PASSWORD=... DRY_RUN=true python3 sync.py --rollback /opt/traefik-dns-sync/backups/192.168.1.2_2026-02-19T221000Z.json

# Execute rollback
PIHOLE_PASSWORD=... python3 sync.py --rollback /opt/traefik-dns-sync/backups/192.168.1.2_2026-02-19T221000Z.json
```

## Error Handling

The script is designed to keep running reliably in unattended environments:

- **Retry with backoff** — failed API requests are retried up to 3 times (configurable) with exponential backoff. Only network errors and 5xx responses are retried; 4xx errors fail immediately.
- **Per-instance resilience** — if one Pi-hole is unreachable or auth fails, the script logs the error and continues syncing to the remaining instances instead of aborting.
- **Traefik unavailable** — if the Traefik API is down or returns invalid data, the script exits cleanly without touching the cache, so the next run will retry.
- **Session cleanup** — Pi-hole API sessions are cleaned up (`DELETE /api/auth`) after every sync, even if errors occur.
- **Exit codes** — `0` success, `1` configuration error, `2` Traefik unreachable, `3` one or more Pi-hole instances failed. Useful for cron alerting.

## Conflict Resolution

If a Traefik-managed hostname already exists in Pi-hole pointing to a different IP, the script will:

1. Log a `WARNING` with the hostname, old IP, and new Traefik IP
2. Back up the current state (as usual)
3. Remove the old entry and let the normal sync add the correct one

This is enabled by default. To log conflicts without removing them, use:

```bash
python3 sync.py --no-replace-conflicts
```

## Managed Entry Scope

The script only manages DNS entries pointing to `TRAEFIK_IP`. Manual entries pointing to other IPs are never touched, unless they conflict with a Traefik-managed hostname (see above).

## Requirements

- **Python 3.6+** — uses only the standard library (no `pip install` needed)
- **Pi-hole v6** — uses the v6 REST API (`/api/config/dns/hosts`). Not compatible with Pi-hole v5, which used `/etc/pihole/custom.list` and had no REST API for DNS management
- **Traefik v2 or v3** — any version that exposes `/api/http/routers` with `Host()` rules
- **Traefik API access** — the API must be reachable from wherever the script runs (localhost if on the same host)
- **Pi-hole application password** — generated in the Pi-hole web UI under Settings → API. Requires `webserver.api.app_sudo` enabled for write access
- **Network access** — the script needs HTTP(S) access to both the Traefik API and all Pi-hole instances

## How This Compares

Other scripts that solve this problem tend to be Docker-first Go applications with built-in schedulers. This script takes a different approach:

| | This script | Other implementations |
|---|---|---|
| **Language** | Python (stdlib only, zero dependencies) | Go (compiled, external dependencies) |
| **Deployment** | Standalone script + cron | Docker container |
| **Multiple Pi-holes** | Yes, with per-instance passwords | Single instance only |
| **Stale record cleanup** | Automatic — removes entries for routers that no longer exist | Not supported |
| **Change detection** | SHA256 hash cache — skips Pi-hole API when nothing changed | Queries both APIs every interval |
| **Backup & rollback** | Auto-backup before sync, `--rollback` to restore | Not supported |
| **Router filtering** | Auto-excludes `@internal`, configurable blocklist | No filtering |
| **Scheduling** | `--daemon` mode or system cron | Built-in cron scheduler |
| **Runtime requirements** | Python 3.6+ | Docker |

## Daemon Mode

The script can run as a long-lived daemon instead of via cron, polling at a configurable interval:

```bash
# Set interval in .env (optional, default is 120 seconds)
SYNC_INTERVAL=120

# Run directly
python3 sync.py --daemon

# Or install the included systemd service
sudo cp traefik-pihole-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now traefik-pihole-sync

# Check status / logs
sudo systemctl status traefik-pihole-sync
sudo journalctl -u traefik-pihole-sync -f
```

The daemon handles `SIGTERM` and `SIGINT` for clean shutdown, and systemd will restart it automatically on failure. One-shot mode (without `--daemon`) still works for cron.

## Tested On

This script has been tested on a clean Debian 13 installation with Traefik running as a native systemd service:

- **Traefik 3.6.7** (codename: ramequin), built 2026-01-14, Go 1.24.11
- **Systemd service**: `/etc/systemd/system/traefik.service` running `/usr/bin/traefik --configFile=/etc/traefik/traefik.yaml`
- **Pi-hole v6** on two separate instances

## License

MIT
