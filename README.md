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

# 3. Generate secrets
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# Run twice — use first output for SESSION_SECRET, second for PAT_HMAC_SECRET

# 4. Disable systemd-resolved if it holds port 53 (common on Ubuntu)
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf

# 5. Set up iptables forwarding for DNS (53 → 5300)
sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5300
sudo iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 5300
sudo apt-get install -y iptables-persistent && sudo netfilter-persistent save

# 6. For first boot: nginx needs SSL certs to start, so temporarily use HTTP-only config
# Comment out the two HTTPS server{} blocks in nginx/conf.d/yourddns.conf, then:
sudo mkdir -p /var/www/certbot
docker compose up -d

# 7. Get SSL certificate
sudo certbot certonly --webroot -w /var/www/certbot \
  -d yourddns.com -d www.yourddns.com \
  --email you@yourddns.com --agree-tos --non-interactive

# 8. Restore the full nginx config (uncomment the HTTPS blocks), then reload
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

## DNS Port Setup

The DNS server binds to port 53 inside the container, mapped to host port **5300** by default (to avoid conflicts with `systemd-resolved` or other services). Use iptables to forward public port 53 → 5300:

```bash
# Forward DNS traffic to the container
sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5300
sudo iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 5300

# Persist rules across reboots
sudo apt-get install -y iptables-persistent
sudo netfilter-persistent save
```

If port 5300 is blocked by a cloud firewall (e.g. DigitalOcean), also open it:
```bash
sudo ufw allow 5300/udp
sudo ufw allow 5300/tcp
```

To verify DNS is working after setup:
```bash
dig @<your-server-ip> yourdomain.d.yourddns.com
```

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
