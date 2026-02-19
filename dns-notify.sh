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

# Lowercase domain for consistent matching
DOMAIN="${DOMAIN,,}"

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

# Ensure state file is writable
if [[ -f "$STATE_FILE" ]] && [[ ! -w "$STATE_FILE" ]]; then
    echo "ERROR: Cannot write to ${STATE_FILE} — check permissions." >&2
    exit 1
fi

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
        tr '[:upper:]' '[:lower:]' | \
        sed 's/[.*+?^${}()|[\]\\]/\\&/g' | \
        sed 's/^/^/' | sed 's/$/$/' | paste -sd'|' - 2>/dev/null || true)
fi

# ── Parse queries ──────────────────────────────────────────────────
# Extract structured data: fqdn, query type, source IP

TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE" "${TMPFILE}".*' EXIT

# Parse each matching log line into: subdomain|type|source_ip|time
echo "$NEW_LINES" | \
    grep -i "${DOMAIN}" | \
    grep -i "query:" | \
    awk -v domain="$DOMAIN" '
    {
        # Extract timestamp (field 2: HH:MM:SS.ms → keep HH:MM)
        ts = $2
        sub(/:[0-9]+\.[0-9]+$/, "", ts)

        # Extract source IP: "client @0xHEX IP#PORT" or "client IP#PORT"
        src_ip = ""
        for (i = 1; i <= NF; i++) {
            if ($i == "client") {
                candidate = $(i+1)
                if (candidate ~ /^@0x/) candidate = $(i+2)
                sub(/#.*/, "", candidate)
                if (candidate ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/)
                    src_ip = candidate
                break
            }
        }

        # Extract FQDN and query type: "query: FQDN IN TYPE"
        fqdn = ""; qtype = ""
        for (i = 1; i <= NF; i++) {
            if ($i == "query:" || $i ~ /^query:$/) {
                fqdn = $(i+1)
                if ($(i+2) == "IN") qtype = $(i+3)
                break
            }
        }

        if (fqdn == "" || src_ip == "") next

        # Strip trailing dot and lowercase
        sub(/\.$/, "", fqdn)
        fqdn = tolower(fqdn)

        # Check if fqdn matches domain
        if (fqdn == domain) {
            sname = "@"
        } else {
            suffix = "." domain
            slen = length(suffix)
            if (length(fqdn) > slen && substr(fqdn, length(fqdn) - slen + 1) == suffix) {
                sname = substr(fqdn, 1, length(fqdn) - slen)
            } else {
                next
            }
        }

        # Deduplicate: only print first occurrence of each subdomain|type|ip
        key = sname "|" qtype "|" src_ip
        if (!(key in seen)) {
            seen[key] = 1
            print sname "|" qtype "|" src_ip "|" ts
        }
    }
    ' > "${TMPFILE}.parsed"

# Nothing matched
if [[ ! -s "${TMPFILE}.parsed" ]]; then
    exit 0
fi

# Get unique subdomains
awk -F'|' '{print $1}' "${TMPFILE}.parsed" | sort -u > "${TMPFILE}.subs"

# Apply blacklist filter
if [[ -n "$BLACKLIST_PATTERN" ]]; then
    grep -ivE "$BLACKLIST_PATTERN" "${TMPFILE}.subs" > "${TMPFILE}.filtered" 2>/dev/null || true
else
    cp "${TMPFILE}.subs" "${TMPFILE}.filtered"
fi

QUERY_COUNT=$(wc -l < "${TMPFILE}.filtered" | tr -d ' ')

if [[ "$QUERY_COUNT" -eq 0 ]]; then
    exit 0
fi

# ── Classify source IPs ────────────────────────────────────────────

# Get unique source IPs and do reverse DNS lookups
awk -F'|' '{print $3}' "${TMPFILE}.parsed" | sort -u > "${TMPFILE}.ips"

declare -A IP_LABELS
while IFS= read -r ip; do
    ptr=$(dig +short -x "$ip" 2>/dev/null | head -1 | sed 's/\.$//' || true)
    ptr_lower="${ptr,,}"
    label=""

    if [[ -z "$ptr" ]]; then
        label="unknown"
    elif [[ "$ptr_lower" =~ googlebot|google\.com$ ]]; then
        label="Google"
    elif [[ "$ptr_lower" =~ bing\.com$|bingbot|msn\.com$ ]]; then
        label="Bing"
    elif [[ "$ptr_lower" =~ yahoo\.(com|net)$|yahoodns ]]; then
        label="Yahoo"
    elif [[ "$ptr_lower" =~ yandex\.(ru|net|com)$ ]]; then
        label="Yandex"
    elif [[ "$ptr_lower" =~ baidu\.(com|jp)$ ]]; then
        label="Baidu"
    elif [[ "$ptr_lower" =~ crawl|spider|bot|scraper ]]; then
        label="bot"
    elif [[ "$ptr_lower" =~ cloudflare|cloudflare-dns ]]; then
        label="Cloudflare"
    elif [[ "$ptr_lower" =~ akamai ]]; then
        label="Akamai"
    elif [[ "$ptr_lower" =~ amazon|aws|ec2|compute\.amazonaws ]]; then
        label="AWS"
    elif [[ "$ptr_lower" =~ azure|microsoft|msft|\.cloud\.microsoft ]]; then
        label="Azure"
    elif [[ "$ptr_lower" =~ google|\.goog$|googleusercontent ]]; then
        label="GCP"
    elif [[ "$ptr_lower" =~ digitalocean ]]; then
        label="DigitalOcean"
    elif [[ "$ptr_lower" =~ linode|akamai ]]; then
        label="Linode/Akamai"
    elif [[ "$ptr_lower" =~ hetzner|your-server\.de ]]; then
        label="Hetzner"
    elif [[ "$ptr_lower" =~ ovh\.net$|ovh\.com$ ]]; then
        label="OVH"
    elif [[ "$ptr_lower" =~ shodan ]]; then
        label="Shodan"
    elif [[ "$ptr_lower" =~ censys ]]; then
        label="Censys"
    elif [[ "$ptr_lower" =~ internetmeasurement|measurement ]]; then
        label="scanner"
    else
        label="$ptr"
    fi

    IP_LABELS["$ip"]="$label"
done < "${TMPFILE}.ips"

# ── Build notification message ──────────────────────────────────────

# Build lines from parsed data, filtering by allowed subdomains
{
    echo "DNS | ${DOMAIN} | $(date '+%Y-%m-%d %H:%M')"
    echo ""

    while IFS='|' read -r sname qtype src_ip ts; do
        # Check if subdomain is in filtered list
        if ! grep -qxF "$sname" "${TMPFILE}.filtered" 2>/dev/null; then
            continue
        fi

        if [[ "$sname" == "@" ]]; then
            display_name="${DOMAIN}"
        else
            display_name="${sname}.${DOMAIN}"
        fi

        lbl="${IP_LABELS[$src_ip]:-unknown}"
        echo "${display_name} | ${qtype} | ${src_ip} (${lbl}) | ${ts}"
    done < "${TMPFILE}.parsed"
} > "$TMPFILE"

# ── Send notification ───────────────────────────────────────────────

NOTIFY_ARGS=(-data "$TMPFILE" -bulk -silent)
if [[ -n "$PROVIDER_ID" ]]; then
    NOTIFY_ARGS+=(-id "$PROVIDER_ID")
fi

notify "${NOTIFY_ARGS[@]}"
