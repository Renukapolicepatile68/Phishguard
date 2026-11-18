# PhishGuard

PhishGuard is a responsive URL-analysis dashboard backed by a Flask API and a
persistent SQLite database. Accounts have private scan history and preferences;
reports and CSV exports are generated from saved account data.

## Run locally

Use Python 3.10+ and Node.js only if you want to run the browser checks. No
frontend build step is required.

1. Install the backend requirements:

   ```powershell
   python -m pip install -r backend\requirements.txt
   ```

2. Start the API from the project root. It listens on all network interfaces
   by default for phone testing:

   ```powershell
   python backend\app.py
   ```

3. In a second terminal, serve the project root at the configured frontend
   origin. With VS Code Live Server, use `http://127.0.0.1:5500` so the session
   cookie is same-site with the API:

   ```powershell
   python -m http.server 5500 --bind 127.0.0.1
   ```

4. Open `http://127.0.0.1:5500/index.html`, create an account, and scan URLs.
   The API health check is at `http://127.0.0.1:5000/api/health`.

### Test on a phone over your local network

Connect the phone and development computer to the same trusted Wi-Fi network.
Use the computer's private IPv4 address (for example `192.168.1.20`) in the
phone's browser. Serve both processes on the LAN interfaces:

```powershell
python backend\app.py
```

In another terminal, allow the phone's frontend origin through CORS and start
the static server:

```powershell
$env:PHISHGUARD_ALLOWED_ORIGINS = "http://192.168.1.20:5500"
python -m http.server 5500 --bind 0.0.0.0
```

Replace the example address with the computer's actual private IP. Open
`http://192.168.1.20:5500/index.html` on the phone. The frontend selects the
API on that same host at port 5000. Allow those ports through the computer's
firewall only on the trusted private network. Service-worker installation
requires HTTPS, except when testing on localhost.

The default bind address `0.0.0.0` exposes the development API to reachable
interfaces. Keep it on a trusted network and do not port-forward it to the
internet. Configure `PHISHGUARD_ALLOWED_ORIGINS` to the exact frontend origin
as shown above; do not use `*` with session credentials.

The SQLite database is stored at `backend\instance\phishguard.db`. Set
`PHISHGUARD_DB_PATH` to use another location.

The backend loads `DATABASE_URL` from the project-root `.env` file when
present; a process environment variable takes precedence. A configured URL
selects PostgreSQL, while an unset or empty `DATABASE_URL` keeps local
development on SQLite. To use SQLite with a Supabase URL still in `.env`, set
`$env:DATABASE_URL = ""` before starting the backend.

## Password reset email

Password reset links are sent over SMTP; the reset endpoint returns a clear
configuration error until a mail server is configured. Set these environment
variables before starting Flask:

```powershell
$env:PHISHGUARD_SMTP_HOST = "smtp.example.com"
$env:PHISHGUARD_SMTP_PORT = "587"
$env:PHISHGUARD_SMTP_USER = "your-smtp-user"
$env:PHISHGUARD_SMTP_PASSWORD = "your-smtp-password"
$env:PHISHGUARD_SMTP_FROM = "security@example.com"
$env:PHISHGUARD_APP_URL = "http://127.0.0.1:5500"
```

Port 587 uses STARTTLS. Set `PHISHGUARD_SMTP_SSL=true` to use implicit TLS
(typically port 465). Reset tokens are random, stored only as hashes, expire
after one hour, and are single-use.

## Production configuration

Set a long random `PHISHGUARD_SECRET_KEY`, `PHISHGUARD_ENV=production`,
`PHISHGUARD_ALLOWED_ORIGINS` to the exact trusted HTTPS frontend origins when
the frontend is on a different origin, and
`PHISHGUARD_APP_URL` to the deployed HTTPS frontend URL. The frontend uses
`/api` on the same origin in production by default; configure
`window.PHISHGUARD_API_URL` before `js/config.js` only when the API has a
separate HTTPS origin. Production cookies require HTTPS. Terminate TLS at a
production reverse proxy or HTTPS host, use a production WSGI server, and do
not expose Flask's development server to the public internet. If the frontend
and API are on different sites (not just different subdomains), set
`PHISHGUARD_COOKIE_SAMESITE=None` and use HTTPS for both.

## Deploy on Render with Supabase

The included [`render.yaml`](./render.yaml) configures one free Render web
service. It serves the frontend and API on the same origin, uses Gunicorn,
binds to Render's `$PORT`, and exposes `/api/health` for health checks. Render
terminates HTTPS, so the deployed `onrender.com` address is the URL to open on
desktop and Android Chrome. No CORS origins are needed for this same-origin
setup.

1. Create a Supabase project and wait for its database to become available.
   In the project settings, copy the **Session pooler** connection string.
   Use the IPv4-compatible session pooler when connecting from Render; do not
   use the transaction pooler. Keep the connection string private.
2. Before pushing the application or starting the Render service, migrate the
   existing local database to the new, empty Supabase database. Stop the
   local application first and avoid writing to its database until migration
   finishes. From the project root in PowerShell, enter the connection string
   when prompted:

   ```powershell
   $env:DATABASE_URL = Read-Host "Supabase session pooler connection string"
   python backend\migrate_sqlite_to_postgres.py
   Remove-Item Env:DATABASE_URL
   ```

   The command makes a timestamped SQLite backup beside the source database,
   refuses a non-empty PostgreSQL destination, copies users, password hashes,
   scan history, reset tokens, and settings transactionally, and verifies row
   counts. It does not modify or delete the original SQLite database. Keep the
   backup in a safe location.
3. Create a private GitHub repository, push the project files, and connect
   that repository to Render using **New > Blueprint**. When Render prompts
   for `DATABASE_URL`, enter the same Supabase connection string in the
   environment-variable form; Render stores it as a secret. The blueprint
   generates `PHISHGUARD_SECRET_KEY`. Wait for the health check to pass and
   open the service's HTTPS URL.
4. Test signup/login, URL scans, CSV uploads, scan history, reports, and PWA
   installation on the deployed HTTPS address. In Android Chrome, use
   **Install app** or **Add to Home screen**. Service workers and installation
   require HTTPS (except localhost).

Do not set `PHISHGUARD_ALLOWED_ORIGINS` for the same-origin deployment. If you
later host the frontend separately, set it to the exact HTTPS frontend origin
and configure the frontend API URL to the HTTPS API origin.

### Free-tier persistence and backups

Render's free service can spin down when idle; its local filesystem is
ephemeral, which is why the app uses Supabase rather than local SQLite in
production. Supabase Free has database size and inactivity limits and does
not include downloadable managed backups. Export the database regularly to
storage outside Supabase and test restoring an export. Never commit database
exports, connection strings, or secret keys to GitHub. Password-reset emails
also require a configured SMTP provider; Render may block common SMTP ports,
so use a provider-supported alternative port or HTTPS email API if delivery
fails.

To keep existing accounts and scans, do not run the migration against a
database that already contains application rows. Perform the migration before
the Render service begins accepting traffic. The migration is one-time; later
production data should be backed up from PostgreSQL, not copied from the old
SQLite file.

## API overview

- `POST /api/signup`, `POST /api/login`, `POST /api/logout`, `GET /api/me`
- `POST /api/forgot-password`, `POST /api/reset-password`
- `POST /api/scan`, `POST /api/bulk-scan`
- `GET /api/history`, `GET|DELETE /api/history/<id>`, `DELETE /api/history`
- `GET /api/analytics`, `GET|PUT /api/settings`, `GET /api/me`, `PUT /api/profile`, `DELETE /api/me`
- `GET /api/history/export.csv`, `GET /api/reports/<url|threat|model>.pdf`

Authenticated write requests require the session's `X-CSRF-Token` returned by
`GET /api/me`. The dashboard sends it automatically.

Bulk scans accept a UTF-8 CSV with one URL per row (up to 500 URLs). Results
are saved to scan history when history storage is enabled and can be downloaded
from the bulk results table as a CSV containing each URL, threat type, and risk
score.

## Analysis limitations

URL classifications are transparent, deterministic heuristics; the project
does not include a trained AI model, browse scanned websites, or query external
domain-reputation or malware feeds. A low risk score is not a safety guarantee.
Avoid entering credentials on unfamiliar sites regardless of a scan result.
Results are labeled Safe (risk 0–29), Phishing (30–59), or Malicious (60–100);
these labels describe heuristic risk bands and are not confirmed threat verdicts.

## Tests

Run the API tests from the backend directory:

```powershell
python -m unittest -v test_app
```
