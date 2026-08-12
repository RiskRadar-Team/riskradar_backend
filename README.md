# RiskRadar Backend

RiskRadar is a REST API for assessing the phishing and scam risk of URLs, emails, and messages. It combines local threat intelligence, rule-based indicators, optional reputation checks, and Gemini analysis to return a risk score, risk level, recommendation, and detailed findings.

## Features

- User authentication with access tokens, refresh-token cookies, password reset OTPs, and role-based access control.
- URL scanning for suspicious structure, blacklisted or whitelisted domains/URLs, phishing keywords, Google Safe Browsing, VirusTotal, and optional Gemini analysis.
- Email scanning for urgency, credential requests, sender and header signals, links, keywords, and optional AI analysis.
- Message scanning for suspicious links, urgency, impersonation, financial/credential requests, and optional AI analysis.
- Persistent scan history, findings, user dashboard, and admin dashboard.
- Admin management of domains, URLs, phishing keywords, users, and reference data.

## Stack

- Node.js with Express 5 (ES modules)
- PostgreSQL via `pg`
- JWT, bcrypt, cookies, CORS, and express-validator
- Google Gemini (`@google/genai`)
- Optional Google Safe Browsing and VirusTotal reputation providers

## Quick start

Prerequisites: Node.js 18+ and PostgreSQL with the `pgcrypto` extension enabled (needed for `gen_random_uuid()`).

```bash
npm install
```

Create a PostgreSQL database, then enable the required extension once:

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
```

Create `.env` from the following template. Keep all secrets out of source control.

```dotenv
PORT=5000
DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/DATABASE
NODE_ENV=development

JWT_SECRET=replace-with-a-long-random-secret
JWT_SECRET_REFRESH=replace-with-a-different-long-random-secret
JWT_ACCESS_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d
REFRESH_TOKEN_EXPIRES_MS=604800000
BCRYPT_SALT_ROUNDS=10

# Optional reputation and AI integrations
GOOGLE_SAFE_BROWSING_API_KEY=
VIRUSTOTAL_API_KEY=
GEMINI_API_KEY=
GEMINI_MODEL=

# Password reset email support
PASSWORD_RESET_OTP_EXPIRES_MINUTES=10
EMAIL_USER=
EMAIL_PASSWORD=
PASSWORD_RESET_TOKEN_SECRET=replace-with-a-long-random-secret
PASSWORD_RESET_TOKEN_EXPIRES_IN=15m
```

Start the API:

```bash
npm run dev
```

The server listens on `http://localhost:5000` by default. On startup it creates the application tables and seeds risk levels, threat types, and keyword categories if they are missing.

## API conventions

All routes begin with `/riskradar`. Protected routes require:

```http
Authorization: Bearer <access-token>
```

Successful responses use this envelope:

```json
{
  "success": true,
  "statusCode": 200,
  "message": "URL scanned successfully.",
  "data": {}
}
```

Errors return `success: false`, a message, and validation errors where applicable. Refresh tokens are stored in an HTTP-only `refreshToken` cookie; send requests with credentials when using a browser client.

## Core workflows

### Authenticate

| Method | Endpoint | Purpose |
| --- | --- | --- |
| POST | `/riskradar/auth/register` | Register a user |
| POST | `/riskradar/auth/login` | Sign in and receive an access token |
| POST | `/riskradar/auth/refresh-token` | Refresh the access token using the cookie |
| POST | `/riskradar/auth/logout` | End the current session |
| POST | `/riskradar/auth/logout-all` | End all sessions |
| POST | `/riskradar/auth/forgot-password` | Send a password-reset OTP |
| POST | `/riskradar/auth/verify-reset-otp` | Verify the OTP and receive a reset token |
| POST | `/riskradar/auth/reset-password` | Set a password with the reset token |

Registration requires `full_name`, `email`, and a password of at least eight characters containing uppercase, lowercase, numeric, and special characters.

### Scan content

| Method | Endpoint | Required body fields |
| --- | --- | --- |
| POST | `/riskradar/scan/url` | `url` |
| POST | `/riskradar/scan/email` | `sender_email` |
| POST | `/riskradar/scan/message` | `message` |

Example URL scan:

```bash
curl -X POST http://localhost:5000/riskradar/scan/url \
  -H "Authorization: Bearer <access-token>" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

Email scans also accept `reply_to`, `return_path`, `subject`, `body`, `attachment_found`, `spf_result`, `dkim_result`, and `dmarc_result`. Message scans accept optional `platform`, `sender`, `sender_id`, and `language`; supported platforms include `SMS`, `WHATSAPP`, `TELEGRAM`, `SLACK`, and `OTHER`.

Scan results contain the parent scan record, scan-specific data, individual findings, the 0–100 score, risk level, phishing flag, recommendation, and aggregate finding statistics.

### View scans and dashboards

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/riskradar/history` | Authenticated user's scan history |
| GET | `/riskradar/history/:scanId` | A scan and its details |
| GET | `/riskradar/dashboard?period=7d` | User dashboard; `7d`, `30d`, `90d`, or `all` |
| GET | `/riskradar/email-scan/:id` | Email scan detail |
| GET | `/riskradar/email-scan/:scanId/scan` | Email scan by parent scan ID |
| GET | `/riskradar/scan-message/:id` | Message scan detail |
| GET | `/riskradar/scan-message/:scanId/scan` | Message scan by parent scan ID |

History supports pagination and filters such as `page`, `limit`, `scanType`, `riskLevel`, `isPhishing`, `from`, and `to`.

## Risk assessment

Each detected signal produces a finding with a severity and a score. Scores are added and capped at 100. The seeded levels are:

| Score | Level | Recommended action |
| --- | --- | --- |
| 0–19 | Safe | Allow |
| 20–39 | Low Risk | Allow |
| 40–69 | Medium Risk | Warn |
| 70–89 | High Risk | Warn |
| 90–100 | Critical | Block |

A scan is classified as phishing at 60+ or immediately when it includes a critical blacklisted-domain or blacklisted-URL finding. Explicit blacklist findings also result in a `BLOCK` recommendation.

## Admin API

All admin routes require an authenticated user with the `ADMIN` role.

- `/riskradar/admin/create` — create an admin user.
- `/riskradar/admin/dashboard` — dashboard with the same period options as the user dashboard.
- `/riskradar/admin/scans` — list or filter all scans; `/riskradar/admin/scans/:scanId` retrieves one.
- `/riskradar/users/admin` — user administration; status, role, and delete actions are available under `/riskradar/users/:id/admin/...`.
- `/riskradar/domain` and `/riskradar/url` — CRUD and active-status controls for domain and URL intelligence.
- `/riskradar/keyword` — CRUD and active-status controls for phishing keywords.
- `/riskradar/threat/all`, `/riskradar/risk/all`, and `/riskradar/keyword-category/all` — reference data.

`Endpoint_Examples/` contains ready-to-import JSON request/response examples for the available endpoints.

## Project layout

```text
index.js                 HTTP server entry point and database bootstrap
src/app.js               Express configuration and route mounting
src/config/              environment, PostgreSQL, and Gemini clients
src/routes/              HTTP route definitions
src/controllers/         request/response handlers
src/services/            scan pipelines and business logic
src/models/              PostgreSQL query layer
src/validations/         express-validator rules
src/middlewares/         authentication, authorization, validation, errors
src/utils/               JWT, cookies, email, errors, and response helpers
Endpoint_Examples/       example API requests and responses
```

## Notes for deployment

- Configure the frontend origin in `src/app.js`; the current CORS allowlist is `http://localhost:5173` and `http://localhost:3000`.
- Reputation checks degrade gracefully when their API keys are omitted. Gemini failures are handled differently by scan type, so configure and test it before relying on AI results in production.
- The repository currently has no automated test suite (`npm test` is a placeholder). Add integration tests for authentication and each scan type before production deployment.
