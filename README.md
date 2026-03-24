# YourDDNS

Self-hosted Dynamic DNS service with multi-user support, account tiers, and a clean dashboard.

## Features

- Multi-user with email/password and OTP (passwordless) login
- Email verification and password recovery via [Resend](https://resend.com)
- Account tiers (Free / Starter / Pro) with configurable limits
- Multiple DNS zones — support first-level subdomains of any delegated domain
- Per-zone tier restrictions (premium-only domains)
- Clean dashboard: records, hit count, last update, enable/disable
- Auto-generated PAT (Personal Access Token) per record — shown once, regeneratable
- DNS resolution logging with hit tracking
- Reports tab with date-range line chart per subdomain
- Admin portal: user management, domain management, blocked IPs, settings, stats
- Login-as-user impersonation for admins
- Docker + nginx + Let's Encrypt ready
- Stripe-ready tier structure (integration TODO)

## DNS Architecture

This app runs its own authoritative DNS server. You configure NS records at your registrar to delegate zones to this server.

**Example setups:**

| Goal | Configure at registrar |
|------|------------------------|
| DDNS at `*.d.yourddns.com` | `d.yourddns.com NS ns1.yourddns.com` |
| DDNS at `*.yourddns.com` (full zone) | `yourddns.com NS ns1.yourddns.com` |
| Add another domain | `ddns.example.com NS ns1.yourddns.com` |

For the full zone approach (`*.yourddns.com`), the Admin → Domains panel lets you add static DNS records (A, MX, CNAME, TXT) alongside DDNS records, so the website A record is managed here too.

## Quick Start (Docker)

```bash
# 1. Clone the repo
git clone https://github.com/yourname/yourddns
cd yourddns

# 2. Configure environment
cp .env.example .env
# Edit .env — set SESSION_SECRET, PAT_HMAC_SECRET, RESEND_API_KEY, ADMIN_EMAIL, ADMIN_PASSWORD

# 3. Generate a session secret (32+ chars)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# 4. Start (HTTP only first, for certbot)
docker compose up -d

# 5. Get SSL certificate
certbot certonly --webroot -w /var/www/certbot -d yourddns.com -d www.yourddns.com

# 6. Reload nginx with HTTPS
docker compose exec nginx nginx -s reload
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SESSION_SECRET` | 32+ char random string for session encryption |
| `PAT_HMAC_SECRET` | Random string for PAT hashing |
| `ADMIN_EMAIL` | Bootstrap admin email (used on first startup only) |
| `ADMIN_PASSWORD` | Bootstrap admin password |
| `RESEND_API_KEY` | Resend API key for emails |
| `EMAIL_FROM` | From address for emails |
| `SITE_NAME` | Display name (also in Admin Settings) |
| `SITE_DOMAIN` | Primary domain |
| `SITE_URL` | Full URL including https:// |
| `DNS_PORT` | DNS server port (default: 53) |
| `DB_PATH` | SQLite database path (default: ./data/yourddns.db) |
| `STRIPE_SECRET_KEY` | Stripe secret key (optional) |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook secret (optional) |

## Update API

Clients update their IP by calling:

```
GET https://yourddns.com/api/update?key=YOUR_PAT&subdomain=home.d.yourddns.com
```

Optionally specify an IP:
```
GET https://yourddns.com/api/update?key=YOUR_PAT&subdomain=home.d.yourddns.com&ip=1.2.3.4
```

Response: `good 1.2.3.4` (changed), `nochg 1.2.3.4` (unchanged), `badauth`, `badip`, `abuse`, `disabled`

## Default Tier Limits

| Tier | Records | Min TTL | Resolutions/hr | Updates/hr | Min Sub Length |
|------|---------|---------|----------------|------------|----------------|
| Free | 3 | 300s | 1,000 | 10 | 4 chars |
| Starter | 10 | 120s | 5,000 | 30 | 3 chars |
| Pro | 50 | 60s | 20,000 | 60 | 2 chars |

All values are configurable in Admin → Settings.

## DNS Record Setup

After deploying, go to **Admin → Domains** and add your first zone (e.g. `d.yourddns.com`).
Configure your registrar:
1. Add glue record: `ns1.yourddns.com A <your-server-ip>`
2. Add NS delegation: `d.yourddns.com NS ns1.yourddns.com`

## Nginx Configuration

The `nginx/conf.d/yourddns.conf` template uses `yourddns.com`. Edit it to match your domain before deployment.

## Customization

All site-level text (site name, domain, support email) is configurable in **Admin → Settings** without redeployment.

## License

MIT
