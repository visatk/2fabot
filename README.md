# 🔐 2FA Bot — Production-Ready Telegram TOTP Authenticator

A zero-cold-start, globally distributed 2FA authenticator bot running on **Cloudflare Workers** + **D1** + **Hono**. Handles TOTP code generation for any TOTP-compatible service (Google, GitHub, AWS, etc.) — all within Telegram.

---

## ✨ Features

| Feature | Detail |
|---|---|
| 🌍 **Global Edge** | Runs in 300+ Cloudflare locations, sub-50ms response |
| 🔐 **Webhook Security** | Constant-time secret token validation (`X-Telegram-Bot-Api-Secret-Token`) |
| 🛡️ **Rate Limiting** | D1-backed per-user rate limiter (20 req/min window) |
| ✏️ **Input Sanitization** | Service name filtering, Base32 validation, message deletion after `/add` |
| 🗑️ **Delete Confirmation** | Two-step confirm before deleting a service |
| ⏱️ **Live Timer Bar** | Visual countdown showing code validity window |
| 🔄 **Refresh Button** | Re-generate code in-place with one tap |
| 📊 **Structured Logging** | JSON logs to Cloudflare Workers Observability |
| 🏥 **Health Endpoint** | `GET /health` for uptime monitoring |
| 🔧 **Auto-Setup** | `GET /setup` registers webhook automatically |
| 💾 **50-service cap** | Per-user limit prevents abuse |

---

## 🚀 Deployment

### 1. Prerequisites

```bash
npm install -g wrangler
wrangler login
```

### 2. Install dependencies

```bash
npm install
```

### 3. Create D1 database

```bash
npm run db:create
# Copy the database_id into wrangler.toml
```

### 4. Run migrations

```bash
# Local dev
npm run db:migrate

# Production
npm run db:migrate:remote
```

### 5. Set secrets

```bash
# Your bot token from @BotFather
npm run secret:token

# Generate a strong webhook secret (64 hex chars)
openssl rand -hex 32
npm run secret:webhook
```

### 6. Deploy

```bash
npm run deploy
```

### 7. Register webhook

After deploy, call the setup endpoint once:

```bash
curl https://your-worker.workers.dev/setup
```

---

## 🤖 Bot Commands

| Command | Description |
|---|---|
| `/start` | Welcome message + quick action button |
| `/help` | Full usage guide |
| `/add <Service> <Secret>` | Add a TOTP service (message auto-deleted after) |
| `/list` | View all services with inline buttons |
| `/manage` | Alias for `/list` |
| `/version` | Show bot version |

---

## 🔒 Security Architecture

```
Telegram → [X-Telegram-Bot-Api-Secret-Token validation]
         → [Rate limit check (D1)]
         → [Input sanitization]
         → [Parameterized D1 queries]
         → [Auto-delete /add messages]
         → [Delete confirmation prompts]
```

### Key security controls:

- **Webhook validation**: Constant-time comparison prevents timing attacks
- **No SQL injection**: All queries use `?` bound parameters
- **Secret auto-delete**: The `/add` command message is deleted immediately after processing so your Base32 secret doesn't sit in chat history
- **Rate limiting**: 20 requests per 60s per user, backed by D1
- **Input sanitization**: Service names stripped of special characters; secrets validated as proper Base32 before storage

---

## 📁 Project Structure

```
2fa-bot/
├── src/
│   └── index.ts          # Main worker — all routes, handlers, logic
├── schema.sql            # D1 table definitions
├── wrangler.toml         # Cloudflare Worker configuration
├── package.json
├── tsconfig.json
└── README.md
```

---

## 🛠️ Local Development

```bash
npm run dev
# Worker runs at http://localhost:8787

# Test health check
curl http://localhost:8787/health
```

Use [Telegram's test environment](https://core.telegram.org/bots/webapps#testing-mini-apps) for local webhook testing, or a tunneling tool like `cloudflared tunnel`.

---

## 📊 Monitoring

Enable Workers Logs in Cloudflare dashboard. All events are structured JSON:

```json
{ "level": "INFO", "msg": "Command received", "userId": 123, "command": "/list", "ts": 1716000000000 }
{ "level": "WARN", "msg": "Rate limit hit", "userId": 456, "ts": 1716000001000 }
```

Health check endpoint for external uptime monitors:

```
GET https://your-worker.workers.dev/health
→ { "status": "ok", "version": "2.0.0", "ts": 1716000000000 }
```

---

## 🔄 Upgrading from v1

The schema adds two new tables (`rate_limits`, `event_log`) and a column (`created_at` on `totp_secrets`). Run the migration file against your existing database — the `IF NOT EXISTS` clauses make it safe to re-run.

---

## 📜 License

MIT
