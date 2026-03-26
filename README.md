# YourDDNS

Self-hosted Dynamic DNS service built for developers. Multi-user, API-driven, with custom domain support and a clean dashboard.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://www.paypal.com/donate?hosted_button_id=REPLACE_WITH_YOUR_BUTTON_ID)

## Support the Project

YourDDNS is free and open-source. If you find it useful, please consider making a donation to help cover server costs and ongoing development.

**[Donate via PayPal →](https://www.paypal.com/donate?hosted_button_id=REPLACE_WITH_YOUR_BUTTON_ID)**

Even a small contribution helps keep the service running for everyone.

---

## Features

- Multi-user with email/password, OTP (passwordless), and Google OAuth login
- Email verification and password recovery via [Resend](https://resend.com)
- Account tiers with configurable limits (records, TTL, lookups, updates)
- Multiple DNS zones — full domain delegation or subdomain-only
- Bring your own domain — validate NS delegation and manage static + DDNS records
- Per-record API tokens (PAT) — shown once, regeneratable
- DNS resolution logging with per-record hit tracking
- Reports tab with date-range charts per subdomain
- IPv4 and IPv6 support (A and AAAA records, independent update endpoints)
- Admin portal: user management, domain management, blocked IPs, settings, stats
- Login-as-user impersonation for admins
- Donation prompts with PayPal integration (optional)
- Docker + Caddy (automatic HTTPS via Let's Encrypt) ready

## DNS Architecture

This app runs its own authoritative DNS server. You configure NS records at your registrar to delegate zones to this server.

| Goal | Configure at registrar |
|------|------------------------|
| DDNS at `*.d.yourddns.com` | `d.yourddns.com NS ns1.yourddns.com` |
| DDNS at `*.yourddns.com` (full zone) | `yourddns.com NS ns1.yourddns.com` |
| User's own domain | `ddns.example.com NS ns1.yourddns.com` |

For full-zone delegation, Admin → Domains lets you manage static DNS records (A, MX, CNAME, TXT) alongside DDNS records.

## Quick Start (Docker)

```bash
# 1. Clone the repo
git clone https://github.com/ryangriggs/yourddns
cd yourddns

# 2. Configure environment
cp .env.example .env
# Edit .env — set SESSION_SECRET, PAT_HMAC_SECRET, RESEND_API_KEY, ADMIN_EMAIL, ADMIN_PASSWORD, SITE_DOMAIN

# 3. Generate secrets
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# Run twice — use outputs for SESSION_SECRET and PAT_HMAC_SECRET

# 4. Disable systemd-resolved if it holds port 53 (common on Ubuntu)
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf

# 5. Set up iptables forwarding for DNS (53 → 5300)
# Scoped to eth0 — prevents Docker's internal DNS from being redirected
sudo iptables -t nat -I PREROUTING -i eth0 -p udp --dport 53 -j REDIRECT --to-port 5300
sudo iptables -t nat -I PREROUTING -i eth0 -p tcp --dport 53 -j REDIRECT --to-port 5300
sudo apt-get install -y iptables-persistent && sudo netfilter-persistent save

# 6. Start
docker compose up -d
```

Caddy handles HTTPS automatically via Let's Encrypt on first startup — no manual certificate steps required.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SESSION_SECRET` | Yes | 32+ char random string for session encryption |
| `PAT_HMAC_SECRET` | Yes | Random string for PAT hashing |
| `ADMIN_EMAIL` | Yes | Bootstrap admin email (first startup only) |
| `ADMIN_PASSWORD` | Yes | Bootstrap admin password |
| `SITE_DOMAIN` | Yes | Primary domain (e.g. `yourddns.com`) |
| `CADDY_EMAIL` | Yes | Email for Let's Encrypt certificate notifications |
| `RESEND_API_KEY` | No | Resend API key for transactional emails |
| `EMAIL_FROM` | No | From address for emails |
| `SITE_NAME` | No | Display name (also configurable in Admin → Settings) |
| `SITE_URL` | No | Full URL including `https://` |
| `GOOGLE_CLIENT_ID` | No | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | No | Google OAuth client secret |
| `DB_PATH` | No | SQLite path (default: `./data/yourddns.db`) |
| `STRIPE_SECRET_KEY` | No | Stripe secret key (optional billing) |

## Update API

Clients update their IP with a single GET request:

```
GET https://yourddns.com/api/update?key=YOUR_PAT&subdomain=home.d.yourddns.com
```

Optional parameters:

| Parameter | Description |
|-----------|-------------|
| `ip` | Set IPv4 explicitly (default: auto-detect from connecting IP) |
| `ip6` | Set IPv6 explicitly |
| `subdomain` | Fully-qualified hostname to update |

Responses: `good 1.2.3.4` (updated), `nochg 1.2.3.4` (no change), `badauth`, `badip`, `abuse`, `disabled`

### Example: cron-based update

```bash
# Update IPv4 and IPv6 every 5 minutes
*/5 * * * * curl -sf "https://yourddns.com/api/update?key=YOUR_PAT&subdomain=home.d.yourddns.com&ip=$(curl -4sf https://api4.ipify.org)" > /dev/null
*/5 * * * * curl -sf "https://yourddns.com/api/update?key=YOUR_PAT&subdomain=home.d.yourddns.com&ip6=$(curl -6sf https://api6.ipify.org)" > /dev/null
```

## Default Tier Limits

| Tier | Records | Min TTL | Resolutions/hr | Updates/hr |
|------|---------|---------|----------------|------------|
| Free | 3 | 300s | 1,000 | 10 |
| Starter | 10 | 120s | 5,000 | 30 |
| Pro | 50 | 60s | 20,000 | 60 |

All values are configurable in Admin → Settings. Subscriptions can be disabled entirely (everyone gets free-tier limits) — useful for running a community or personal instance.

## DNS Port Setup

The DNS server binds to port **5300** (no root required), exposed on host port 5300. Public port 53 is forwarded to 5300 via iptables.

```bash
# Scoped to eth0 — do NOT omit -i eth0 or Docker containers will be unable
# to resolve external DNS during builds and at runtime
sudo iptables -t nat -I PREROUTING -i eth0 -p udp --dport 53 -j REDIRECT --to-port 5300
sudo iptables -t nat -I PREROUTING -i eth0 -p tcp --dport 53 -j REDIRECT --to-port 5300
sudo apt-get install -y iptables-persistent && sudo netfilter-persistent save
```

Verify DNS is working:
```bash
dig @<your-server-ip> yourdomain.d.yourddns.com
```

## Customization

All site-level settings (name, domain, support email, PayPal donation URL, etc.) are configurable in **Admin → Settings** without redeployment.

## License

MIT
