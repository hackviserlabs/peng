<p align="center">
  <img src="public/logo.svg" alt="peng" width="120" />
</p>

<h1 align="center">peng</h1>

<p align="center">
  Open-source penetration test report writing tool.<br/>
  Write, manage, and export professional pentest reports — fast.
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#getting-started">Getting Started</a> •
  <a href="#docker-deployment">Docker Deployment</a> •
  <a href="#usage">Usage</a> •
  <a href="#tech-stack">Tech Stack</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a>
</p>

---

## Why peng?

Most pentest report tools are either expensive SaaS platforms or clunky desktop apps. **peng** is a free, open-source alternative. The default static build stores reports in your browser. The Docker deployment stores them in a self-hosted SQLite database.

## Features

- **45+ Finding Templates** — Pre-written descriptions, impact statements, and remediation steps for common vulnerabilities (SQLi, XSS, SSRF, IDOR, and more)
- **Rich Text Editor** — Full WYSIWYG editor with formatting, images, code blocks, and lists
- **Report Export** — Print-ready report generation and JSON data export/import
- **Multi-Project Support** — Manage multiple assessments independently
- **CVSS Scoring** — Built-in CVSS v3.1 score input with automatic severity mapping
- **Metadata Fields** — Endpoint, parameter, affected host, port, CVE, CWE per finding
- **Offline Mode** — The static build uses IndexedDB and works without an account
- **Dark Theme** — Professional dark UI designed for long assessment sessions

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) 24 LTS and npm

### Installation

```bash
git clone https://github.com/IgorDuino/peng.git
cd peng
npm ci
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

### Build for Production

```bash
npm run build
npm run preview
```

The production build will be in the `dist/` directory. You can deploy it to any static hosting provider (Vercel, Netlify, GitHub Pages, etc.).

## Docker Deployment

Both modes use the same `compose.yaml`. Run these steps from the repository root.

1. For a new deployment, create the gitignored `.env` from the example. The command refuses to overwrite an existing file.

   ```bash
   (umask 077; set -C; cat .env.example > .env)
   ```

2. In `.env`, set `DEPLOY_MODE=local` for a trusted loopback workspace without sign-in, or `DEPLOY_MODE=organization` for signed-in access. Before the first organization startup on a volume, including when promoting a local workspace, set `ADMIN_USERNAME=admin` and set `ADMIN_PASSWORD` to a strong password generated with `openssl rand -hex 24`. Later organization startups use the account saved in the volume. An existing installation with no `DEPLOY_MODE` set defaults to `organization`.
3. Build and start the stack, then open the printed address in your browser. In organization mode, sign in with the bootstrapped account.

   ```bash
   docker compose up --build -d --wait &&
   docker compose port web 8080
   ```

### Switch modes or apply settings

To switch an existing deployment, edit `DEPLOY_MODE` in your existing `.env`. Keep any existing credentials. If you are switching to organization mode for the first time on this volume, add the bootstrap credentials from step 2. Keep the same Compose project name so both modes use the same `peng-data` volume. Compose defaults the project name to the checkout directory. Avoid `docker compose down -v`, which deletes the volume.

Apply `.env` changes with `docker compose up -d --wait`. Run `docker compose port web 8080` to check the address.

### Connect an MCP client

Both modes use Streamable HTTP.

- **Local.** Connect to `http://<printed-address>/mcp` without a key. Call `list_projects` to find the project's ID, then pass it as `projectId` to `list_templates`, `get_template`, and `append_finding`.
- **Organization.** Create a named key under **MCP access** in project settings and copy it while it is visible. Use the displayed endpoint and send `Authorization: Bearer <key>`. The key selects the project, so start with `list_templates` using `{}`. Revoke the key when the agent's work is done.

### Ports and HTTPS

Compose publishes nginx on `127.0.0.1`. The default `PENG_PORT=0` picks a free port. Set `PENG_PORT=43103` in `.env` for a fixed port. Keep local mode on loopback.

For organization mode over HTTPS, point your TLS reverse proxy at the fixed loopback port, preserve the public `Host`, set `X-Forwarded-Proto: https`, and allow streaming responses on `/mcp`. Set `APP_ORIGIN=https://your-public-host` and `COOKIE_SECURE=true` in `.env`, then run `docker compose up -d --wait`.

Set writing instructions in project settings and have the agent read them with `list_templates` before submitting a finding. Reuse the same idempotency key when retrying. Findings appear in the open editor after the next refresh. To move reports from the static browser workspace to Docker, export JSON from the static app and import it in Docker. See the [backend reference](server/README.md) for API and MCP tool inputs.

## Usage

1. **Create a Project** — Click "New Project" and give it a name (e.g., "Acme Corp Q1 2026")
2. **Add Findings** — Use the template browser to pick from 45+ pre-written templates, or create a blank finding
3. **Edit Details** — Use the rich text editor to customize descriptions, impact, remediation, and proof of concept
4. **Add Metadata** — Click "Add property" to include endpoint, parameters, CVSS score, CVE/CWE references
5. **Export** — Generate a print-ready report or export as JSON for backup/sharing

## Template Categories

| Category | Templates |
|---|---|
| Injection | SQL Injection (Union, Blind Boolean, Blind Time), NoSQL, OS Command, SSTI, LDAP, XPath |
| XSS | Reflected, Stored, DOM-Based |
| Access Control | IDOR, Privilege Escalation, Path Traversal, CORS Misconfiguration |
| Authentication | Brute Force, JWT Weak Secret, Session Fixation, Insecure Password Reset |
| API Security | BOLA, Mass Assignment |
| Misconfiguration | Debug Mode, Directory Listing, Default Credentials, Missing Security Headers |
| SSL/TLS | Expired Certificate, Weak Cipher Suites, Missing HSTS |
| Business Logic | Race Condition, Price Manipulation |
| Cloud | S3 Bucket Misconfiguration, IAM Over-Privileged |
| Cryptographic | Weak Hashing, Cleartext Transmission |
| Information Disclosure | Stack Trace Exposure, Version Disclosure |
| Network | Open Ports, Outdated Software |
| Mobile | Insecure Data Storage, Certificate Pinning |
| Other | CSRF, Clickjacking, Open Redirect |

## Tech Stack

- **React** + **TypeScript**
- **Vite** — Build tool
- **Tailwind CSS** — Styling
- **Tiptap** — Rich text editor
- **IndexedDB** — Client-side storage
- **Lucide** — Icons

## Contributing

Contributions are welcome! Feel free to open issues and pull requests.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

## License

This project is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE) for details.

---

<p align="center">
  Made by <a href="https://github.com/hackviserr">hackviserr</a>
</p>
