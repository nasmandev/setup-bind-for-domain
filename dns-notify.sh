#!/usr/bin/env bash
set -euo pipefail

# dns-notify.sh — Batched DNS query notifications via projectdiscovery/notify
#
# Reads new lines from BIND9 query.log since the last run, deduplicates,
# filters, and sends a single batched notification.
#
# Usage:
#   dns-notify.sh -d example.com [-l /var/log/named/query.log] [-b /etc/dns-notify/blacklist.txt] [-i slack]

# ── Defaults ────────────────────────────────────────────────────────

LOGFILE="/var/log/named/query.log"
BLACKLIST="/etc/dns-notify/blacklist.txt"
STATE_DIR="/var/lib/dns-notify"
DOMAIN=""
PROVIDER_ID=""

# ── Usage ───────────────────────────────────────────────────────────

usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") -d DOMAIN [-l LOGFILE] [-b BLACKLIST] [-i PROVIDER_ID]

  -d DOMAIN       Domain to monitor (required)
  -l LOGFILE      Path to BIND query log (default: /var/log/named/query.log)
  -b BLACKLIST    Path to blacklist file (default: /etc/dns-notify/blacklist.txt)
  -i ID           Notify provider ID (default: all configured providers)
EOF
    exit 1
}

# ── Parse arguments ─────────────────────────────────────────────────

while getopts ":d:l:b:i:" opt; do
    case $opt in
        d) DOMAIN="$OPTARG" ;;
        l) LOGFILE="$OPTARG" ;;
        b) BLACKLIST="$OPTARG" ;;
        i) PROVIDER_ID="$OPTARG" ;;
        *) usage ;;
    esac
done

[[ -n "$DOMAIN" ]] || usage

# ── Verify dependencies ────────────────────────────────────────────

# Ensure PATH includes common install locations (cron has a minimal PATH)
export PATH="/usr/local/bin:/usr/local/go/bin:/usr/local/go-tools/bin:${PATH}"

if ! command -v notify &>/dev/null; then
    echo "ERROR: 'notify' (projectdiscovery/notify) is not installed." >&2
    echo "Run SetupBindForDomain.sh to install it, or manually:" >&2
    echo "  go install -v github.com/projectdiscovery/notify/cmd/notify@latest" >&2
    exit 1
fi

# ── State management ───────────────────────────────────────────────

mkdir -p "$STATE_DIR"
STATE_FILE="${STATE_DIR}/offset.state"

# Read saved state (inode and byte offset)
SAVED_INODE=0
SAVED_OFFSET=0
if [[ -f "$STATE_FILE" ]]; then
    SAVED_INODE=$(awk 'NR==1' "$STATE_FILE")
    SAVED_OFFSET=$(awk 'NR==2' "$STATE_FILE")
fi

# Check current log file
if [[ ! -f "$LOGFILE" ]]; then
    exit 0  # No log file yet — nothing to do
fi

CURRENT_INODE=$(stat -c '%i' "$LOGFILE" 2>/dev/null || stat -f '%i' "$LOGFILE" 2>/dev/null)
FILE_SIZE=$(stat -c '%s' "$LOGFILE" 2>/dev/null || stat -f '%z' "$LOGFILE" 2>/dev/null)

# Reset offset on log rotation (inode changed) or if file is smaller than offset
if [[ "$CURRENT_INODE" -ne "$SAVED_INODE" ]] || [[ "$FILE_SIZE" -lt "$SAVED_OFFSET" ]]; then
    SAVED_OFFSET=0
fi

# No new data
if [[ "$FILE_SIZE" -eq "$SAVED_OFFSET" ]]; then
    exit 0
fi

# ── Extract new lines ──────────────────────────────────────────────

NEW_LINES=$(tail -c +"$((SAVED_OFFSET + 1))" "$LOGFILE")

# Save new state
echo "$CURRENT_INODE" > "$STATE_FILE"
echo "$FILE_SIZE" >> "$STATE_FILE"

# ── Load blacklist ──────────────────────────────────────────────────

BLACKLIST_PATTERN=""
if [[ -f "$BLACKLIST" ]]; then
    # Build grep pattern from blacklist (lines that aren't comments or empty)
    # Matches exact subdomain names since .subs file contains only subdomain parts
    BLACKLIST_PATTERN=$(grep -v '^\s*#' "$BLACKLIST" | grep -v '^\s*$' | \
        sed 's/^/^/' | sed 's/$/$/' | paste -sd'|' - 2>/dev/null || true)
fi

# ── Filter and deduplicate ──────────────────────────────────────────

ESCAPED_DOMAIN="${DOMAIN//./\\.}"

TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT

echo "$NEW_LINES" | \
    grep -i "${DOMAIN}" | \
    grep -oP "query: \K\S+" | \
    grep -iE "\.${ESCAPED_DOMAIN}\.$|^${ESCAPED_DOMAIN}\.$" | \
    while IFS= read -r fqdn; do
        # Strip trailing dot
        fqdn="${fqdn%.}"
        # Extract subdomain part
        sub="${fqdn%."${DOMAIN}"}"
        [[ "$sub" == "$DOMAIN" ]] && sub="@"
        echo "$sub"
    done | sort -u > "${TMPFILE}.subs"

# Apply blacklist filter
if [[ -n "$BLACKLIST_PATTERN" ]]; then
    grep -ivE "$BLACKLIST_PATTERN" "${TMPFILE}.subs" > "${TMPFILE}.filtered" 2>/dev/null || true
else
    cp "${TMPFILE}.subs" "${TMPFILE}.filtered"
fi

# Also extract source IPs for dedup: subdomain+IP pairs
echo "$NEW_LINES" | \
    grep -i "${DOMAIN}" | \
    grep -oP "client\s+(@0x[a-f0-9]+\s+)?\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
    paste - <(echo "$NEW_LINES" | \
        grep -i "${DOMAIN}" | \
        grep -oP "query: \K\S+" | \
        sed 's/\.$//' \
    ) 2>/dev/null | \
    sort -u > "${TMPFILE}.pairs" 2>/dev/null || true

# Count unique source IPs per subdomain for summary
QUERY_COUNT=$(wc -l < "${TMPFILE}.filtered" | tr -d ' ')

if [[ "$QUERY_COUNT" -eq 0 ]]; then
    rm -f "${TMPFILE}.subs" "${TMPFILE}.filtered" "${TMPFILE}.pairs"
    exit 0
fi

# ── Build notification message ──────────────────────────────────────

{
    echo "DNS Queries for ${DOMAIN} ($(date '+%Y-%m-%d %H:%M')):"
    echo "---"
    while IFS= read -r sub; do
        [[ -z "$sub" ]] && continue
        if [[ "$sub" == "@" ]]; then
            query_fqdn="${DOMAIN}"
        else
            query_fqdn="${sub}.${DOMAIN}"
        fi
        # Count unique source IPs for this subdomain from the pairs file
        ip_count=$(grep -c "${query_fqdn}$" "${TMPFILE}.pairs" 2>/dev/null || echo "?")
        echo "  ${query_fqdn} (${ip_count} source(s))"
    done < "${TMPFILE}.filtered"
    echo "---"
    echo "Total unique subdomains: ${QUERY_COUNT}"
} > "$TMPFILE"

# ── Send notification ───────────────────────────────────────────────

NOTIFY_ARGS=(-data "$TMPFILE" -bulk -silent)
if [[ -n "$PROVIDER_ID" ]]; then
    NOTIFY_ARGS+=(-id "$PROVIDER_ID")
fi

notify "${NOTIFY_ARGS[@]}"

# Cleanup handled by trap
rm -f "${TMPFILE}.subs" "${TMPFILE}.filtered" "${TMPFILE}.pairs"
