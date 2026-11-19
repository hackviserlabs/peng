# Peng backend

The backend serves the browser API and the Streamable HTTP MCP endpoint on one port. It uses a file-backed SQLite database and shares the app's finding defaults and template catalog.

## Run

Use Node.js 22 or later. Run these commands from the repository root for a local HTTP setup.

```sh
cd server
npm ci
ADMIN_USERNAME=admin ADMIN_PASSWORD='replace-with-a-strong-password' COOKIE_SECURE=false npm start
```

| Environment variable | Behavior |
| --- | --- |
| `PORT` | Defaults to `3000` on `0.0.0.0`. Use `0` for an ephemeral port. |
| `DATABASE_PATH` | Defaults to `./data/peng.sqlite3` relative to the process working directory. Mount the parent directory on a persistent, writable volume for the database and its SQLite WAL files. |
| `COOKIE_SECURE` | Defaults to `true`. Set to `false` for local plain HTTP. |
| `APP_ORIGIN` | Set to the browser-facing origin, including the scheme and any non-default port, such as `https://reports.example.com`. The server verifies the incoming Host against this origin. When unset, the server expects an HTTP origin derived from the request Host. |
| `ADMIN_USERNAME`, `ADMIN_PASSWORD` | Required together on first startup with an empty database. Startup against a populated database can omit them. The saved credentials are kept on subsequent startups. |

Run `npm test` from `server/` to exercise the API and both MCP protocol modes. Tests bind to ephemeral loopback ports and use in-memory or temporary SQLite databases.

## Docker and nginx

Install production dependencies with `npm ci --omit=dev` in `server/`. Build from a repository-root context and preserve the relative paths of `server/`, `src/types/`, and `src/data/templates/` in the backend image. Start the backend in `server/` with `npm start`. Keep the backend port on the private Docker network and expose nginx to clients.

Serve the frontend and proxy the API and MCP on the same nginx origin. With an upstream Docker service named `backend`, the following locations can go in the frontend's nginx server block. Set `APP_ORIGIN` to the public HTTPS origin and keep `COOKIE_SECURE=true`.

```nginx
location /api/ {
    client_max_body_size 16m;
    proxy_set_header Host $http_host;
    proxy_pass http://backend:3000;
}

location = /mcp {
    client_max_body_size 256k;
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header Connection "";
    proxy_buffering off;
    proxy_pass http://backend:3000;
}

location = /healthz {
    proxy_pass http://backend:3000;
}
```

`GET /healthz` returns `200` with `{"status":"ok"}` when the backend is running and can query SQLite.

## Browser API

Use relative URLs from the frontend. Login sets a host-only, HttpOnly, SameSite=Strict session cookie scoped to `/api` that expires after seven days. Logout revokes the session. All API mutations, including login and logout, require an exact same-origin `Origin` header, which browsers send on same-origin fetch mutations. Send that header explicitly in scripted API clients.

| Method and path | Body and response |
| --- | --- |
| `GET /api/session` | `200 {username}` with a valid session, or `401`. |
| `POST /api/login` | JSON `{username,password}`. Returns `200 {username}` and sets the session cookie, or `401` for invalid credentials. |
| `POST /api/logout` | `204` and clears the session cookie. |
| `GET /api/projects` | Array of the session owner's projects. |
| `PUT /api/projects/:id` | Upserts the full app `Project`. Returns `204`. Omit optional `templateInstructions` to keep the saved value or send an empty string to clear it. |
| `DELETE /api/projects/:id` | Deletes the project, findings and keys. Returns `204`. |
| `GET /api/projects/:id/findings` | Array of findings for the project. |
| `PUT /api/projects/:id/findings/:findingId` | Upserts one full app `Finding`. Returns `204`. |
| `DELETE /api/projects/:id/findings/:findingId` | Deletes one finding. Returns `204`. |
| `GET /api/projects/:id/keys` | Array of `{id,name,createdAt}` records with ISO 8601 timestamps. |
| `POST /api/projects/:id/keys` | JSON `{name}`. Returns `201 {key}`. Copy the bearer key at creation. SQLite stores its SHA-256 digest. |
| `DELETE /api/projects/:id/keys/:keyId` | Revokes a key immediately. Returns `204`. |

Project and finding IDs in PUT bodies must match the path. The browser API preserves rich text fields used by the app editor.

## MCP

Configure the client for Streamable HTTP at `https://reports.example.com/mcp` with an `Authorization: Bearer <key>` header on every request. The endpoint supports modern per-request MCP and legacy stateless Streamable HTTP.

- **`list_templates`** takes an empty object and returns the project's `templateInstructions` and template summaries with `id`, `title`, `category`, and `severity`.
- **`append_finding`** requires `title` and a caller-generated `idempotencyKey`. It accepts an optional `severity` (defaults to `Medium`) and plain-text `description`, `poc`, `requestResponse`, `impact`, `remediation`, `notes`, `references`, `url`, `method`, `parameter`, `affectedHost`, `port`, `cve`, `cwe`, `cvss`, and `cvssVector`. It creates an `Open` finding in the bearer key's project and returns `{findingId,created}`. The backend escapes content fields for the HTML renderer.

Retry a submission with the same idempotency key and finding content. A retry returns the original finding ID and `created: false`, even after a restart, a key rotation, or deletion of that finding. Reusing a key with different content returns a tool error. Idempotency keys are scoped to each project and are removed with the project.
