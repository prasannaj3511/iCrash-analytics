# iCrash Analytics

Self-hosted, Sentry-style crash and error tracking. Multi-user, multi-project, on **PostgreSQL**, with SDKs for the browser and Node.js.

## Setup

Requires Node >= 22.9 and a PostgreSQL server (12+).

```bash
npm install
cp .env.example .env      # then set DATABASE_URL to your Postgres user/password
npm run db:sync           # creates the database, tables, super admin and demo data
npm start                 # http://localhost:4100
```

`npm run db:sync` is idempotent. It creates the database if it doesn't exist (the Postgres user needs `CREATEDB`; otherwise create an empty database first), applies [server/schema.sql](server/schema.sql), and seeds:

- **Super admin**: `prasannaj@ithena.ai` / `Ithena@1234` (override with `SUPERADMIN_EMAIL`, `SUPERADMIN_PASSWORD`, `SUPERADMIN_NAME` before the first sync). Re-running never resets an existing password.
- A **demo project** (`demo-shop`) with sample issues and events, owned by the super admin.

> **Change the super admin password** (Account button, bottom of the sidebar) before exposing the server to anyone.

## How access works

| Role | Can do |
|---|---|
| **Super admin** | Create, disable, delete users and reset their passwords. Sees every project. |
| **User** | Signs in, creates their own projects and keys, sees only their own projects and issues. |

There is no self-signup: the super admin creates accounts (Users page) and shares the credentials. Sessions are HttpOnly cookies stored server-side (hashed), passwords use scrypt, failed logins are throttled, and state-changing API calls require a CSRF header. Set `COOKIE_SECURE=true` when serving over HTTPS.

## Config (`.env`)

| Var | Default | Meaning |
|---|---|---|
| `DB_HOST` `DB_PORT` `DB_USER` `DB_NAME` | localhost / 5432 / postgres / icrash_analytics | Postgres connection |
| `DB_PASS` or `DB_PASS_ENCRYPTED` + `DB_PASS_IV` + `ENCRYPTION_KEY` | | Password, plain or AES-256-CBC hex (decrypted at startup). `DATABASE_URL` overrides all of these. |
| `DATABASE_SSL` | `false` | Use TLS to Postgres |
| `PORT` | `4100` | HTTP port |
| `SUPERADMIN_*` | see above | Seed account |
| `SMTP_HOST` `SMTP_PORT` `SMTP_USER` `SMTP_FROM_EMAIL` + `SMTP_PASS` or `SMTP_PASS_ENCRYPTED`/`SMTP_PASS_IV` | | Email via SMTP (e.g. AWS SES). Optional: app works without it. |
| `APP_URL` | `http://localhost:PORT` | Public URL used in email links |
| `ICRASH_ALERTS` | `true` | New-issue / regression alert emails to the project owner |
| `COOKIE_SECURE` | `false` | Mark session cookie `Secure` |
| `SESSION_DAYS` | `7` | Login lifetime |
| `ICRASH_RETENTION_DAYS` | `30` | Events older than this are purged |
| `ICRASH_MAX_EVENTS_PER_ISSUE` | `100` | Stored events per issue (counters keep growing) |

## Using it in an app

The in-app **User guide** (sidebar) walks through this with your project's real DSN. In short: create a project, copy its DSN (`http://PUBLIC_KEY@host:4100/PROJECT_ID`) from the **Setup** tab, then:

**Browser**
```html
<script src="http://localhost:4100/sdk/icrash.js"></script>
<script>ICrash.init({ dsn: '...', environment: 'production', release: '1.0.0' });</script>
```

**Node.js** (`npm i /path/to/icrash-analytics/sdk/node`)
```js
const icrash = require('@icrash/node');
icrash.init({ dsn: '...', release: '1.0.0' });
app.use(icrash.requestHandler());
// routes
app.use(icrash.errorHandler());
```

**Any language**: `POST /api/:projectId/ingest` with header `x-icrash-key` and a JSON body (`type`, `message`, `level`, `stack`, `environment`, `release`, `user`, `tags`, `extra`, `breadcrumbs`).

Send sample events to a project with `node examples/seed.js "<DSN>"`.

## Notes
- Events group into issues by error type + throw-site frame. Override with `fingerprint: ['my','key']`. A resolved issue reopens when it recurs.
- Use `beforeSend(event)` in either SDK to scrub data. The Node SDK redacts `authorization`/`cookie` headers.
- **Emails** (when SMTP is configured): welcome email on user creation, notice on password reset (passwords are never emailed; the admin shares them), and an alert to the project owner on a new issue or a regression (max 10 per project per hour, not for info/debug levels). A mail failure never blocks sign-ups or ingest.
- Not included yet: source-map un-minifying, Slack alerts, self-service password reset by email.
# iCrash-analytics
