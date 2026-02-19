# setup-bind-for-domain

A shell script that installs and configures BIND9 as an authoritative DNS server with **wildcard resolution** and **query logging** for a given domain on Debian/Ubuntu systems.

Designed for authorized penetration testing — use unique subdomains as probes (e.g. `probe01.yourdomain.com`) to detect blind/out-of-band vulnerabilities such as blind SSRF, blind XXE, blind SQL injection with DNS exfiltration, and similar issues where a target system performs a DNS lookup you can observe.

## How it works

The zone is configured with a wildcard CNAME record (`* IN CNAME`), which means **every subdomain** under the configured domain resolves to the same IP address. Combined with query logging, this lets you:

1. Inject a unique probe domain (e.g. `ssrf-test.yourdomain.com`) into a test payload
2. Monitor the query log on your DNS server
3. If the probe domain appears in the log, the target performed a DNS lookup — confirming the vulnerability

## What the script does

1. Installs BIND9 (if not already installed)
2. Creates a DNS zone with wildcard resolution (`*.domain` → domain IP)
3. Enables query logging to `/var/log/named/query.log`
4. Hardens `named.conf.options` (disables zone transfers, hides version)
5. Validates the configuration with `named-checkconf` and `named-checkzone` before restarting

The script is idempotent — it can be run multiple times without duplicating configuration.

## Requirements

- Debian or Ubuntu
- Root privileges
- A domain with its NS records pointing to the server running this script

## Usage

```bash
sudo bash SetupBindForDomain.sh
```

The script will prompt for:

- **Domain name** — e.g. `example.com`
- **IP address** — the public IPv4 address of this server

## Example

```
$ sudo bash SetupBindForDomain.sh
Enter the domain name (e.g. example.com): example.com
Enter the IP address for example.com: 203.0.113.10
=> bind9 is already installed.
=> Adding zone for example.com to named.conf.local …
=> Writing zone file /etc/bind/zones/db.example.com …
=> Hardening named.conf.options …
=> Enabling query logging …
=> Creating logging configuration …
=> Checking configuration …
=> Restarting bind9 …
=> Done! DNS for example.com → 203.0.113.10 is now active.
=>
=> Wildcard DNS is configured — any subdomain (e.g. probe01.example.com) resolves to 203.0.113.10.
=> Query log: /var/log/named/query.log
=>
=> To monitor incoming DNS lookups in real time:
=>   tail -f /var/log/named/query.log
=>
=> To filter for a specific probe:
=>   tail -f /var/log/named/query.log | grep probe01
```

## Monitoring DNS probes

After setup, monitor incoming lookups in real time:

```bash
# Watch all queries
tail -f /var/log/named/query.log

# Filter for a specific probe
tail -f /var/log/named/query.log | grep probe01

# Show only queries for your domain (ignore noise)
tail -f /var/log/named/query.log | grep example.com
```

When a target system resolves your probe domain, you will see a line like:

```
19-Feb-2026 14:23:07.123 client @0x... 198.51.100.5#43210 (probe01.example.com): query: probe01.example.com IN A +
```

This confirms the target at `198.51.100.5` performed a DNS lookup for `probe01.example.com`.

## DNS records created

| Record | Type  | Value              | Purpose |
|--------|-------|--------------------|---------|
| @      | A     | *provided IP*      | Root domain resolution |
| ns1    | A     | *provided IP*      | Nameserver address |
| @      | NS    | ns1.*domain*.      | Nameserver delegation |
| *      | CNAME | *domain*.          | **Wildcard** — all subdomains resolve to the same IP |

## Files modified

| File | Description |
|------|-------------|
| `/etc/bind/named.conf.local` | Zone declaration |
| `/etc/bind/zones/db.<domain>` | Zone file with wildcard record |
| `/etc/bind/named.conf.options` | Security hardening + query logging enabled |
| `/etc/bind/named.conf` | Include for log config |
| `/etc/bind/named.conf.log` | Logging configuration (separate query log channel) |

## Log files

| File | Content |
|------|---------|
| `/var/log/named/query.log` | All DNS queries (use this to detect probes) |
| `/var/log/named/bind.log` | General BIND operational log |

## Notifications

Instead of watching the query log manually, you can receive **batched notifications** using [`projectdiscovery/notify`](https://github.com/projectdiscovery/notify). The included `dns-notify.sh` script runs via cron, deduplicates queries, filters noise, and sends a single summary message per interval.

Supported providers:

| Provider | Use case |
|----------|----------|
| **Slack** | Team channels |
| **Discord** | Team/community servers |
| **Telegram** | Mobile push via bot |
| **Microsoft Teams** | Corporate environments |
| **Google Chat** | Google Workspace teams |
| **Email (SMTP)** | Any inbox (Gmail, Mailgun, self-hosted) |
| **Pushover** | Mobile push notifications (iOS/Android) |
| **Gotify** | Self-hosted push notifications |
| **Custom Webhook** | Any HTTP endpoint (SIEM, n8n, Zapier, etc.) |

You can enable multiple providers at the same time. Use `-i <id>` to target a specific one.

### Installing notify

```bash
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
```

### Configuring a provider

The setup script will offer to copy the example config automatically. To do it manually:

```bash
mkdir -p ~/.config/notify
cp provider-config.yaml.example ~/.config/notify/provider-config.yaml
```

Then edit `~/.config/notify/provider-config.yaml` — uncomment the provider(s) you want and fill in your credentials. See `provider-config.yaml.example` for all options and setup links.

### Cron setup

The setup script can install the cron job automatically (it will prompt you). To set it up manually:

```bash
# Run every 5 minutes
*/5 * * * * /path/to/dns-notify.sh -d example.com
```

#### dns-notify.sh flags

| Flag | Description | Default |
|------|-------------|---------|
| `-d DOMAIN` | Domain to monitor (required) | — |
| `-l LOGFILE` | Path to BIND query log | `/var/log/named/query.log` |
| `-b BLACKLIST` | Path to blacklist file | `/etc/dns-notify/blacklist.txt` |
| `-i ID` | Notify provider ID | all configured providers |

### Blacklist configuration

Edit `/etc/dns-notify/blacklist.txt` to suppress notifications for noisy subdomains (e.g. `www`, `mail`, `autodiscover`) that scanners probe automatically. One subdomain per line; lines starting with `#` are comments.

See `blacklist.txt.example` for a starter list.

### Example notification output

```
DNS | example.com | 2026-02-19 14:25

ssrf-probe.example.com | A | 198.51.100.5 (unknown) | 14:23
xxe-test.example.com | A | 74.63.22.234 (Hetzner) | 14:24
xxe-test.example.com | AAAA | 74.63.22.234 (Hetzner) | 14:24
xxe-test.example.com | A | 51.12.224.79 (Azure) | 14:24
callback.example.com | HTTPS | 172.71.5.101 (Cloudflare) | 14:25
```

Each line represents a unique combination of subdomain, query type, and source IP. Sources are classified via reverse DNS lookup (Google, Bing, AWS, Azure, Cloudflare, Shodan, Hetzner, etc.).

### Troubleshooting

To reprocess the entire query log (e.g. after fixing a configuration issue), reset the state file:

```bash
echo -e "0\n0" > /var/lib/dns-notify/offset.state
```

To test manually:

```bash
bash -x dns-notify.sh -d example.com
```

If the state file has wrong permissions (e.g. owned by root when cron runs as your user):

```bash
sudo chown $USER /var/lib/dns-notify/offset.state
```
