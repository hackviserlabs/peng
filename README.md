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
git clone https://github.com/hackviserr/peng.git
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

Use Docker with the Compose plugin and a checkout that includes `server/`. Copy `.env.example` to `.env` and set `ADMIN_USERNAME` and `ADMIN_PASSWORD`. Then run:

```bash
docker compose up --build -d --wait
docker compose port web 8080
```

Open the displayed loopback address over HTTP and sign in with the admin credentials. The default `PENG_PORT=0` picks a free port. Set `PENG_PORT=43103` in `.env` for a fixed address. The only published service is nginx, which serves the frontend and forwards `/api/`, `/mcp` (Streamable HTTP), and the `/healthz` readiness check on the same origin. nginx accepts request bodies up to 32 MiB.

Keep `COOKIE_SECURE=false` for local HTTP. For HTTPS, point your TLS reverse proxy at a fixed loopback port, preserve the public `Host`, set `X-Forwarded-Proto: https`, and allow streaming responses on `/mcp`. Set `APP_ORIGIN=https://your-public-host` and `COOKIE_SECURE=true` in `.env` and rerun `docker compose up -d` to apply it.

The server image installs dependencies from `server/package-lock.json` and runs `npm start` on Node 24. The server binds to `0.0.0.0:3000` inside Compose and stores SQLite at `/data/peng.sqlite`.

Compose uses the worktree directory name as the project name by default. Choose a distinct `COMPOSE_PROJECT_NAME` in each `.env` if directory names collide. Each project has its own `peng-data` volume. `docker compose down` preserves it, while `docker compose down -v` deletes it and the reports it holds.

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
