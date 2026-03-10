#!/usr/bin/env python3
"""
traefik-pihole-sync: Automatically sync Traefik router hostnames to Pi-hole v6 local DNS.

Polls the Traefik API for HTTP routers, extracts Host() hostnames, and pushes
them to one or more Pi-hole v6 instances via the Pi-hole REST API.

Configuration is via environment variables (see defaults below).

Exit codes:
  0 — Success (or no changes needed)
  1 — Configuration error (missing required env vars)
  2 — Traefik API unreachable or returned invalid data
  3 — One or more Pi-hole instances failed during sync
"""

import argparse
import glob
import hashlib
import json
import logging
import os
import re
import signal
import sys
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# Exit codes
EXIT_OK = 0
EXIT_CONFIG_ERROR = 1
EXIT_TRAEFIK_ERROR = 2
EXIT_PIHOLE_ERROR = 3

# SSL context for Pi-hole self-signed certs
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

# ---------------------------------------------------------------------------
# Configuration (all via environment variables)
# ---------------------------------------------------------------------------
TRAEFIK_URL = os.environ.get("TRAEFIK_URL", "http://127.0.0.1:8080")
TRAEFIK_IP = os.environ.get("TRAEFIK_IP", "")

PIHOLE_HOSTS = [h.strip() for h in os.environ.get("PIHOLE_HOSTS", "").split(",") if h.strip()]
PIHOLE_PASSWORD = os.environ.get("PIHOLE_PASSWORD", "")
# Per-instance passwords: PIHOLE_PASSWORD_<IP_WITH_UNDERSCORES> (e.g. PIHOLE_PASSWORD_192_168_1_2)
# Falls back to PIHOLE_PASSWORD if not set.
PIHOLE_SCHEME = os.environ.get("PIHOLE_SCHEME", "https")
PIHOLE_PORT = os.environ.get("PIHOLE_PORT", "443")

EXCLUDE_ROUTERS = set(filter(None, os.environ.get("EXCLUDE_ROUTERS", "").split(",")))
EXCLUDE_PROVIDERS = set(filter(None, os.environ.get("EXCLUDE_PROVIDERS", "internal").split(",")))

CACHE_FILE = os.environ.get("CACHE_FILE", "/opt/traefik-dns-sync/.last_hash")
BACKUP_DIR = os.environ.get("BACKUP_DIR", "/opt/traefik-dns-sync/backups")
BACKUP_RETAIN = int(os.environ.get("BACKUP_RETAIN", "10"))
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"

# Retry settings
RETRY_ATTEMPTS = int(os.environ.get("RETRY_ATTEMPTS", "3"))
RETRY_BACKOFF_BASE = float(os.environ.get("RETRY_BACKOFF_BASE", "2.0"))

# Daemon settings
SYNC_INTERVAL = int(os.environ.get("SYNC_INTERVAL", "120"))  # seconds

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
    level=logging.DEBUG if os.environ.get("DEBUG") else logging.INFO,
)
log = logging.getLogger("traefik-pihole-sync")

# Regex to extract hostnames from Traefik rules like: Host(`foo.local`)
HOST_RE = re.compile(r"Host\(`([^`]+)`\)")


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only — no external dependencies)
# ---------------------------------------------------------------------------
def api_request(url, method="GET", data=None, headers=None, timeout=10):
    """Make an HTTP request and return (status_code, parsed_json | None)."""
    headers = headers or {}
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        ctx = _SSL_CTX if url.startswith("https") else None
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        log.error("%s %s -> %d: %s", method, url, e.code, raw[:200])
        return e.code, None
    except urllib.error.URLError as e:
        log.error("%s %s -> %s", method, url, e.reason)
        return 0, None


def api_request_with_retry(url, method="GET", data=None, headers=None, timeout=10):
    """Wrap api_request() with retry logic and exponential backoff.

    Retries on network errors (status 0) and server errors (5xx).
    Does NOT retry on client errors (4xx) — those indicate a real problem.
    """
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        status, result = api_request(url, method=method, data=data, headers=headers, timeout=timeout)

        # Success or client error — return immediately
        if status != 0 and status < 500:
            return status, result

        # Retriable failure
        if attempt < RETRY_ATTEMPTS:
            delay = RETRY_BACKOFF_BASE ** (attempt - 1)  # 1s, 2s, 4s ...
            log.warning(
                "Attempt %d/%d failed for %s %s (status %d) — retrying in %.1fs",
                attempt, RETRY_ATTEMPTS, method, url, status, delay,
            )
            time.sleep(delay)
        else:
            log.error(
                "All %d attempts failed for %s %s (last status %d)",
                RETRY_ATTEMPTS, method, url, status,
            )

    return status, result


# ---------------------------------------------------------------------------
# Traefik
# ---------------------------------------------------------------------------
def fetch_traefik_routers():
    """GET /api/http/routers from Traefik. Returns list of router dicts or None on failure."""
    url = f"{TRAEFIK_URL}/api/http/routers"
    status, data = api_request_with_retry(url)
    if status != 200 or data is None:
        log.error("Failed to fetch Traefik routers (status %d)", status)
        return None

    # Validate: response must be a list
    if not isinstance(data, list):
        log.error("Traefik returned unexpected data type (expected list, got %s)", type(data).__name__)
        return None

    return data


def extract_hostnames(routers):
    """
    Parse Host(`...`) from each router's rule field.
    Applies provider and name-based exclusion filters.
    Returns a sorted, deduplicated list of hostnames.
    """
    hostnames = set()

    for router in routers:
        name = router.get("name", "")
        provider = router.get("provider", "")
        rule = router.get("rule", "")

        # Filter: skip excluded providers (e.g. "internal")
        if provider in EXCLUDE_PROVIDERS:
            log.debug("Skipping router %s (provider=%s)", name, provider)
            continue

        # Filter: skip explicitly excluded router names
        if name in EXCLUDE_ROUTERS:
            log.debug("Skipping router %s (blocklisted)", name)
            continue

        # Extract all Host() values from the rule
        matches = HOST_RE.findall(rule)
        if not matches:
            log.debug("Skipping router %s (no Host rule found)", name)
            continue

        for host in matches:
            hostnames.add(host)

    return sorted(hostnames)


# ---------------------------------------------------------------------------
# Change detection
# ---------------------------------------------------------------------------
def compute_hash(hostnames):
    """SHA256 of the sorted hostname list."""
    content = "\n".join(f"{TRAEFIK_IP} {h}" for h in hostnames)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def has_changed(current_hash):
    """Return True if the hash differs from the cached value (or no cache exists)."""
    try:
        with open(CACHE_FILE, "r") as f:
            cached = f.read().strip()
        return cached != current_hash
    except FileNotFoundError:
        return True


def save_cache(current_hash):
    """Persist the current hash to the cache file."""
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    with open(CACHE_FILE, "w") as f:
        f.write(current_hash)


# ---------------------------------------------------------------------------
# Pi-hole v6 API
# ---------------------------------------------------------------------------
def pihole_url(host):
    """Build the base API URL for a Pi-hole instance."""
    return f"{PIHOLE_SCHEME}://{host}:{PIHOLE_PORT}/api"


def pihole_password_for(host):
    """Return the password for a specific Pi-hole host, falling back to the global default."""
    env_key = f"PIHOLE_PASSWORD_{host.replace('.', '_')}"
    return os.environ.get(env_key, PIHOLE_PASSWORD)


class PiholeAuthError(Exception):
    """Raised when Pi-hole authentication fails."""
    pass


def pihole_authenticate(host):
    """
    POST /api/auth to obtain a session.
    Returns (sid, headers_dict).
    Raises PiholeAuthError on failure instead of exiting.
    """
    url = f"{pihole_url(host)}/auth"
    password = pihole_password_for(host)
    status, data = api_request_with_retry(url, method="POST", data={"password": password})
    if status != 200 or data is None:
        raise PiholeAuthError(f"Auth failed for Pi-hole {host} (status {status})")

    session = data.get("session", {})
    sid = session.get("sid")
    csrf = session.get("csrf")
    if not sid:
        raise PiholeAuthError(f"No SID returned from Pi-hole {host}: {data}")

    headers = {"X-FTL-SID": sid}
    if csrf:
        headers["X-FTL-CSRF"] = csrf
    return sid, headers


def pihole_logout(host, sid):
    """DELETE /api/auth — clean up the Pi-hole session."""
    url = f"{pihole_url(host)}/auth"
    headers = {"X-FTL-SID": sid}
    status, _ = api_request(url, method="DELETE", headers=headers)
    if status in (200, 204, 410):
        log.debug("Session cleaned up for Pi-hole %s", host)
    else:
        log.warning("Session cleanup returned status %d for Pi-hole %s", status, host)


def pihole_get_hosts(host, headers):
    """
    GET /api/config/dns/hosts — returns list of "IP hostname" strings
    that are currently configured on this Pi-hole.
    """
    url = f"{pihole_url(host)}/config/dns/hosts"
    status, data = api_request_with_retry(url, headers=headers)
    if status != 200 or data is None:
        log.error("Failed to fetch DNS hosts from Pi-hole %s (status %d)", host, status)
        return []

    # The API returns {"config": {"dns": {"hosts": ["ip host", ...]}}}
    try:
        hosts = data["config"]["dns"]["hosts"]
    except (KeyError, TypeError):
        log.warning("Unexpected response structure from Pi-hole %s: %s", host, str(data)[:200])
        return []

    # Validate: hosts must be a list
    if not isinstance(hosts, list):
        log.warning("Pi-hole %s returned non-list for hosts (got %s)", host, type(hosts).__name__)
        return []

    return hosts


def pihole_add_host(host, headers, entry):
    """PUT /api/config/dns/hosts/{entry} — add a DNS record."""
    encoded = urllib.parse.quote(entry, safe="")
    url = f"{pihole_url(host)}/config/dns/hosts/{encoded}"
    status, _ = api_request_with_retry(url, method="PUT", headers=headers)
    return status in (200, 201)


def pihole_delete_host(host, headers, entry):
    """DELETE /api/config/dns/hosts/{entry} — remove a DNS record."""
    encoded = urllib.parse.quote(entry, safe="")
    url = f"{pihole_url(host)}/config/dns/hosts/{encoded}"
    status, _ = api_request_with_retry(url, method="DELETE", headers=headers)
    return status in (200, 204)


# ---------------------------------------------------------------------------
# Backup & rollback
# ---------------------------------------------------------------------------
def backup_pihole_hosts(host, headers):
    """
    Save the current DNS host entries for a Pi-hole instance to a
    timestamped JSON file. Returns the backup file path.
    """
    entries = pihole_get_hosts(host, headers)
    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
    path = os.path.join(BACKUP_DIR, f"{host}_{timestamp}.json")
    with open(path, "w") as f:
        json.dump({"host": host, "timestamp": timestamp, "entries": entries}, f, indent=2)
    log.info("Backed up %d entries from %s -> %s", len(entries), host, path)
    return path


def prune_backups():
    """Remove old backup files, keeping the most recent BACKUP_RETAIN per host."""
    for host in PIHOLE_HOSTS:
        pattern = os.path.join(BACKUP_DIR, f"{host}_*.json")
        files = sorted(glob.glob(pattern))
        if len(files) > BACKUP_RETAIN:
            for old in files[: len(files) - BACKUP_RETAIN]:
                os.remove(old)
                log.debug("Pruned old backup: %s", old)


def rollback(backup_file):
    """
    Restore Pi-hole DNS hosts from a backup file.
    Reads the backup, diffs against current state, and applies changes
    to bring Pi-hole back to the backed-up state.
    """
    with open(backup_file, "r") as f:
        backup = json.load(f)

    backed_up_entries = set(backup["entries"])
    backup_host = backup.get("host")
    targets = [backup_host] if backup_host else PIHOLE_HOSTS

    for host in targets:
        log.info("Rolling back %s from %s ...", host, backup_file)
        sid, headers = pihole_authenticate(host)
        try:
            current_entries = set(pihole_get_hosts(host, headers))

            to_add = backed_up_entries - current_entries
            to_remove = current_entries - backed_up_entries

            for entry in sorted(to_add):
                if DRY_RUN:
                    log.info("[DRY RUN] Would restore to %s: %s", host, entry)
                elif pihole_add_host(host, headers, entry):
                    log.info("Restored to %s: %s", host, entry)
                else:
                    log.error("Failed to restore to %s: %s", host, entry)

            for entry in sorted(to_remove):
                if DRY_RUN:
                    log.info("[DRY RUN] Would remove from %s: %s", host, entry)
                elif pihole_delete_host(host, headers, entry):
                    log.info("Removed from %s: %s", host, entry)
                else:
                    log.error("Failed to remove from %s: %s", host, entry)

            log.info("Rollback complete for %s: +%d -%d", host, len(to_add), len(to_remove))
        finally:
            pihole_logout(host, sid)


# ---------------------------------------------------------------------------
# Sync logic
# ---------------------------------------------------------------------------
def sync_pihole(host, desired_hostnames, replace_conflicts=True):
    """
    Sync the desired hostname set to a single Pi-hole instance.
    Returns (added_list, removed_list, conflict_list, had_errors).
    Raises PiholeAuthError if authentication fails.

    If replace_conflicts is True, existing DNS entries for Traefik-managed
    hostnames that point to a different IP will be removed and replaced.
    """
    sid, headers = pihole_authenticate(host)
    try:
        current_entries = pihole_get_hosts(host, headers)

        # Backup current state before making changes
        backup_pihole_hosts(host, headers)

        # Build a map of hostname -> list of IPs from current entries
        current_by_hostname = {}
        for entry in current_entries:
            parts = entry.split(" ", 1)
            if len(parts) == 2:
                current_by_hostname.setdefault(parts[1], []).append(parts[0])

        # Detect and handle conflicting entries (same hostname, different IP)
        conflicts = []
        for hostname in desired_hostnames:
            existing_ips = current_by_hostname.get(hostname, [])
            for ip in existing_ips:
                if ip != TRAEFIK_IP:
                    old_entry = f"{ip} {hostname}"
                    conflicts.append(old_entry)
                    if replace_conflicts:
                        if DRY_RUN:
                            log.warning(
                                "[DRY RUN] CONFLICT on %s: %s points to %s (would replace with %s)",
                                host, hostname, ip, TRAEFIK_IP,
                            )
                        else:
                            log.warning(
                                "CONFLICT on %s: %s points to %s — replacing with %s",
                                host, hostname, ip, TRAEFIK_IP,
                            )
                            if not pihole_delete_host(host, headers, old_entry):
                                log.error("Failed to remove conflicting entry from %s: %s", host, old_entry)
                    else:
                        log.warning(
                            "CONFLICT on %s: %s points to %s (not replacing — use default or omit --no-replace-conflicts)",
                            host, hostname, ip,
                        )

        # Build sets for comparison — only consider entries matching TRAEFIK_IP
        desired_entries = {f"{TRAEFIK_IP} {h}" for h in desired_hostnames}
        current_traefik = {e for e in current_entries if e.startswith(f"{TRAEFIK_IP} ")}

        to_add = desired_entries - current_traefik
        to_remove = current_traefik - desired_entries

        added = []
        removed = []
        errors = False

        for entry in sorted(to_add):
            if DRY_RUN:
                log.info("[DRY RUN] Would add to %s: %s", host, entry)
            else:
                if pihole_add_host(host, headers, entry):
                    log.debug("Added to %s: %s", host, entry)
                else:
                    log.error("Failed to add to %s: %s", host, entry)
                    errors = True
                    continue
            added.append(entry.split(" ", 1)[1])

        for entry in sorted(to_remove):
            if DRY_RUN:
                log.info("[DRY RUN] Would remove from %s: %s", host, entry)
            else:
                if pihole_delete_host(host, headers, entry):
                    log.debug("Removed from %s: %s", host, entry)
                else:
                    log.error("Failed to remove from %s: %s", host, entry)
                    errors = True
                    continue
            removed.append(entry.split(" ", 1)[1])

        return added, removed, conflicts, errors
    finally:
        pihole_logout(host, sid)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Sync Traefik router hostnames to Pi-hole v6 local DNS.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
environment variables:
  TRAEFIK_URL          Traefik API base URL (default: http://127.0.0.1:8080)
  TRAEFIK_IP           IP address of your Traefik instance (required)
  PIHOLE_HOSTS         Comma-separated Pi-hole IPs (required)
  PIHOLE_PASSWORD      Pi-hole admin password (required)
  PIHOLE_SCHEME        http or https (default: https)
  PIHOLE_PORT          Pi-hole web port (default: 443)
  EXCLUDE_ROUTERS      Comma-separated router names to skip (default: none)
  EXCLUDE_PROVIDERS    Comma-separated providers to skip (default: internal)
  CACHE_FILE           Path to hash cache file (default: /opt/traefik-dns-sync/.last_hash)
  BACKUP_DIR           Path to backup directory (default: /opt/traefik-dns-sync/backups)
  BACKUP_RETAIN        Number of backups to keep per Pi-hole host (default: 10)
  DRY_RUN              Set to 'true' to preview changes without applying (default: false)
  DEBUG                Set to any value to enable debug logging
  RETRY_ATTEMPTS       Number of retry attempts for failed requests (default: 3)
  RETRY_BACKOFF_BASE   Base for exponential backoff in seconds (default: 2.0)
  SYNC_INTERVAL        Seconds between sync cycles in --daemon mode (default: 120)

exit codes:
  0  Success (or no changes needed)
  1  Configuration error (missing required env vars)
  2  Traefik API unreachable or returned invalid data
  3  One or more Pi-hole instances failed during sync

examples:
  # Normal sync (e.g. from cron)
  PIHOLE_PASSWORD=secret python3 sync.py

  # Preview what would change without modifying anything
  PIHOLE_PASSWORD=secret DRY_RUN=true python3 sync.py

  # Sync with debug logging and a custom router blocklist
  PIHOLE_PASSWORD=secret DEBUG=1 EXCLUDE_ROUTERS="dashboard@docker,test@file" python3 sync.py

  # List available backups
  python3 sync.py --list-backups

  # Rollback to a previous state (dry run first)
  PIHOLE_PASSWORD=secret DRY_RUN=true python3 sync.py --rollback /opt/traefik-dns-sync/backups/192.168.1.2_2026-02-19T221000Z.json

  # Rollback for real
  PIHOLE_PASSWORD=secret python3 sync.py --rollback /opt/traefik-dns-sync/backups/192.168.1.2_2026-02-19T221000Z.json

  # Run as a daemon (polls every SYNC_INTERVAL seconds)
  python3 sync.py --daemon
""",
    )
    parser.add_argument(
        "--rollback",
        metavar="FILE",
        help="Restore Pi-hole DNS hosts from a backup JSON file instead of syncing.",
    )
    parser.add_argument(
        "--list-backups",
        action="store_true",
        help="List available backup files and exit.",
    )
    parser.add_argument(
        "--no-replace-conflicts",
        action="store_true",
        help="Log conflicting DNS entries but do not remove them. By default, entries for Traefik-managed hostnames pointing to a different IP are replaced.",
    )
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Run continuously, syncing every SYNC_INTERVAL seconds (default: 120). Replaces cron.",
    )
    return parser.parse_args()


def run_sync(replace_conflicts=True):
    """Execute a single sync cycle. Returns an exit code (does not call sys.exit)."""
    # Step 1: Fetch routers from Traefik
    routers = fetch_traefik_routers()
    if routers is None:
        log.error("Cannot reach Traefik API — aborting (cache untouched)")
        return EXIT_TRAEFIK_ERROR
    log.debug("Fetched %d routers from Traefik", len(routers))

    # Step 2: Extract and filter hostnames
    hostnames = extract_hostnames(routers)
    log.debug("Resolved %d unique hostnames: %s", len(hostnames), ", ".join(hostnames))

    # Step 3: Change detection
    current_hash = compute_hash(hostnames)
    if not has_changed(current_hash):
        log.info("NO CHANGE (%d hostnames)", len(hostnames))
        return EXIT_OK

    # Step 4: Sync to each Pi-hole instance (per-instance resilience)
    all_added = []
    all_removed = []
    all_conflicts = []
    failed_hosts = []

    for host in PIHOLE_HOSTS:
        log.info("Syncing to Pi-hole %s ...", host)
        try:
            added, removed, conflicts, errors = sync_pihole(host, hostnames, replace_conflicts)
            all_added.extend(added)
            all_removed.extend(removed)
            all_conflicts.extend(conflicts)
            if errors:
                failed_hosts.append(host)
        except PiholeAuthError as e:
            log.error("Skipping Pi-hole %s: %s", host, e)
            failed_hosts.append(host)
        except Exception as e:
            log.error("Unexpected error syncing to Pi-hole %s: %s", host, e)
            failed_hosts.append(host)

    # Step 5: Update cache and prune old backups
    if not DRY_RUN:
        if not failed_hosts:
            save_cache(current_hash)
        else:
            log.warning(
                "Errors on %d/%d Pi-hole(s) (%s) — cache NOT updated (will retry next run)",
                len(failed_hosts), len(PIHOLE_HOSTS), ", ".join(failed_hosts),
            )
        prune_backups()

    # Step 6: Log summary
    added_unique = sorted(set(all_added))
    removed_unique = sorted(set(all_removed))
    conflict_unique = sorted(set(all_conflicts))
    summary = "SYNC: +%d -%d" % (len(added_unique), len(removed_unique))
    if conflict_unique:
        summary += " ~%d conflicts" % len(conflict_unique)
    log.info(
        "%s | added: %s | removed: %s",
        summary,
        ", ".join(added_unique) if added_unique else "(none)",
        ", ".join(removed_unique) if removed_unique else "(none)",
    )

    return EXIT_PIHOLE_ERROR if failed_hosts else EXIT_OK


def main():
    args = parse_args()

    # Verify required configuration
    if not TRAEFIK_IP:
        log.error("TRAEFIK_IP is not set")
        sys.exit(EXIT_CONFIG_ERROR)
    if not PIHOLE_HOSTS:
        log.error("PIHOLE_HOSTS is not set")
        sys.exit(EXIT_CONFIG_ERROR)
    has_password = bool(PIHOLE_PASSWORD) or any(
        os.environ.get(f"PIHOLE_PASSWORD_{h.replace('.', '_')}")
        for h in PIHOLE_HOSTS
    )
    if not has_password:
        log.error("No Pi-hole password configured. Set PIHOLE_PASSWORD or per-instance PIHOLE_PASSWORD_<IP>.")
        sys.exit(EXIT_CONFIG_ERROR)

    # --list-backups: show available backups and exit
    if args.list_backups:
        pattern = os.path.join(BACKUP_DIR, "*.json")
        files = sorted(glob.glob(pattern))
        if not files:
            print("No backups found.")
        else:
            for f in files:
                print(f)
        return

    # --rollback: restore from backup and exit
    if args.rollback:
        rollback(args.rollback)
        return

    replace_conflicts = not args.no_replace_conflicts

    # --daemon: run continuously
    if args.daemon:
        log.info("Starting daemon mode (interval=%ds)", SYNC_INTERVAL)
        shutdown = False

        def handle_signal(signum, frame):
            nonlocal shutdown
            log.info("Received signal %d — shutting down", signum)
            shutdown = True

        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)

        while not shutdown:
            run_sync(replace_conflicts)
            # Sleep in small increments so we can respond to signals promptly
            for _ in range(SYNC_INTERVAL):
                if shutdown:
                    break
                time.sleep(1)

        log.info("Daemon stopped")
        return

    # One-shot mode (default, cron-compatible)
    rc = run_sync(replace_conflicts)
    if rc != EXIT_OK:
        sys.exit(rc)


if __name__ == "__main__":
    main()
