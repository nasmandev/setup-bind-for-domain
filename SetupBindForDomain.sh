#!/usr/bin/env bash
set -euo pipefail

# ── Helpers ──────────────────────────────────────────────────────────

err()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "=> $*"; }

# ── Must run as root ─────────────────────────────────────────────────

[[ $EUID -eq 0 ]] || err "This script must be run as root (use sudo)."

# ── Collect input ────────────────────────────────────────────────────

read -rp "Enter the domain name (e.g. example.com): " DOMAIN
read -rp "Enter the IP address for ${DOMAIN}: " IP

# Basic validation
[[ -n "$DOMAIN" ]] || err "Domain name cannot be empty."
[[ "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] \
    || err "Invalid domain name: ${DOMAIN}"
[[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] \
    || err "Invalid IPv4 address: ${IP}"

# ── Install bind9 if needed ──────────────────────────────────────────

if ! dpkg -s bind9 &>/dev/null; then
    info "Installing bind9 …"
    apt-get update -qq
    apt-get install -y -qq bind9
else
    info "bind9 is already installed."
fi

# ── Zone configuration ───────────────────────────────────────────────

ZONE_DIR="/etc/bind/zones"
ZONE_FILE="${ZONE_DIR}/db.${DOMAIN}"
SERIAL=$(date +%Y%m%d01)

mkdir -p "$ZONE_DIR"

# Add zone to named.conf.local (skip if already present)
if ! grep -q "zone \"${DOMAIN}\"" /etc/bind/named.conf.local 2>/dev/null; then
    info "Adding zone for ${DOMAIN} to named.conf.local …"
    cat >> /etc/bind/named.conf.local <<EOF

zone "${DOMAIN}" {
    type master;
    file "${ZONE_FILE}";
};
EOF
else
    info "Zone ${DOMAIN} already exists in named.conf.local — skipping."
fi

# Write zone file (overwrite to allow re-runs with updated data)
info "Writing zone file ${ZONE_FILE} …"
cat > "$ZONE_FILE" <<EOF
\$TTL 1d
\$ORIGIN ${DOMAIN}.

@       IN      SOA     ns1.${DOMAIN}. admin.${DOMAIN}. (
                ${SERIAL}       ; Serial
                12h             ; Refresh
                15m             ; Retry
                3w              ; Expire
                2h              ; Minimum TTL
        )

        IN      NS      ns1.${DOMAIN}.

ns1     IN      A       ${IP}
@       IN      A       ${IP}
*       IN      CNAME   ${DOMAIN}.
EOF

chown root:bind "$ZONE_FILE"
chmod 644 "$ZONE_FILE"

# ── Harden named.conf.options ────────────────────────────────────────

OPTS_FILE="/etc/bind/named.conf.options"
if ! grep -q 'allow-transfer' "$OPTS_FILE" 2>/dev/null; then
    info "Hardening named.conf.options …"
    sed -i '/listen-on-v6/a\\tallow-transfer { none; };\n\tversion "not disclosed";' "$OPTS_FILE"
else
    info "named.conf.options already hardened — skipping."
fi

# Enable query logging so every DNS lookup is recorded
if ! grep -q 'querylog' "$OPTS_FILE" 2>/dev/null; then
    info "Enabling query logging …"
    sed -i '/^options {/a\\tquerylog yes;' "$OPTS_FILE"
else
    info "Query logging already enabled — skipping."
fi

# ── Logging ──────────────────────────────────────────────────────────

LOG_DIR="/var/log/named"
LOG_CONF="/etc/bind/named.conf.log"

mkdir -p "$LOG_DIR"
chown bind:bind "$LOG_DIR"

if [[ ! -f "$LOG_CONF" ]]; then
    info "Creating logging configuration …"
    cat > "$LOG_CONF" <<'EOF'
logging {
    channel bind_log {
        file "/var/log/named/bind.log" versions 3 size 5m;
        severity info;
        print-category yes;
        print-severity yes;
        print-time yes;
    };
    channel query_log {
        file "/var/log/named/query.log" versions 5 size 10m;
        severity info;
        print-time yes;
    };
    category default        { bind_log; };
    category update          { bind_log; };
    category update-security { bind_log; };
    category security        { bind_log; };
    category queries         { query_log; };
    category lame-servers    { null; };
};
EOF
else
    info "Logging configuration already exists — skipping."
fi

# Include log config in named.conf (if not already present)
if ! grep -q 'named.conf.log' /etc/bind/named.conf 2>/dev/null; then
    echo 'include "/etc/bind/named.conf.log";' >> /etc/bind/named.conf
fi

# ── Validate & restart ───────────────────────────────────────────────

info "Checking configuration …"
named-checkconf
named-checkzone "$DOMAIN" "$ZONE_FILE"

info "Restarting bind9 …"
systemctl restart bind9

info "Done! DNS for ${DOMAIN} → ${IP} is now active."
info ""
info "Wildcard DNS is configured — any subdomain (e.g. probe01.${DOMAIN}) resolves to ${IP}."
info "Query log: /var/log/named/query.log"
info ""
info "To monitor incoming DNS lookups in real time:"
info "  tail -f /var/log/named/query.log"
info ""
info "To filter for a specific probe:"
info "  tail -f /var/log/named/query.log | grep probe01"

# ── Optional: DNS query notifications via notify ────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NOTIFY_SCRIPT="${SCRIPT_DIR}/dns-notify.sh"

echo ""
read -rp "Set up batched DNS query notifications via projectdiscovery/notify? [y/N] " SETUP_NOTIFY

if [[ "${SETUP_NOTIFY,,}" == "y" ]]; then
    # Check for notify
    if ! command -v notify &>/dev/null; then
        info "WARNING: 'notify' is not installed."
        info "Install it with: go install -v github.com/projectdiscovery/notify/cmd/notify@latest"
        info "Then configure ~/.config/notify/provider-config.yaml (see provider-config.yaml.example)"
        info ""
    fi

    # Install blacklist
    mkdir -p /etc/dns-notify
    if [[ ! -f /etc/dns-notify/blacklist.txt ]]; then
        if [[ -f "${SCRIPT_DIR}/blacklist.txt.example" ]]; then
            cp "${SCRIPT_DIR}/blacklist.txt.example" /etc/dns-notify/blacklist.txt
            info "Installed blacklist to /etc/dns-notify/blacklist.txt"
        fi
    else
        info "Blacklist already exists at /etc/dns-notify/blacklist.txt — skipping."
    fi

    # Create state directory
    mkdir -p /var/lib/dns-notify

    # Install cron job
    if [[ -f "$NOTIFY_SCRIPT" ]]; then
        CRON_LINE="*/5 * * * * ${NOTIFY_SCRIPT} -d ${DOMAIN}"
        if crontab -l 2>/dev/null | grep -qF "dns-notify.sh"; then
            info "Cron job for dns-notify.sh already exists — skipping."
        else
            (crontab -l 2>/dev/null; echo "$CRON_LINE") | crontab -
            info "Installed cron job: ${CRON_LINE}"
        fi
    else
        info "WARNING: dns-notify.sh not found at ${NOTIFY_SCRIPT}"
        info "Copy it to ${SCRIPT_DIR}/ and add a cron entry manually:"
        info "  */5 * * * * ${NOTIFY_SCRIPT} -d ${DOMAIN}"
    fi

    info ""
    info "Notification setup complete."
    info "Edit /etc/dns-notify/blacklist.txt to filter noisy subdomains."
    info "Configure your notification provider in ~/.config/notify/provider-config.yaml"
    info "See provider-config.yaml.example for Slack, Discord, Telegram, Teams, Email, and more."
fi
