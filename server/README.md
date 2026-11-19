# Peng backend

The backend serves the browser API and the Streamable HTTP MCP endpoint on one port. It uses a file-backed SQLite database and can search the app's template catalog when the frontend sources are present.

## Run

Use Node.js 22 or later. Run these commands from the repository root for a standalone local workspace.

```sh
cd server
npm ci
DEPLOY_MODE=local PORT=0 npm start
```

To run an organization workspace over HTTP, generate a password with `openssl rand -hex 24` and save it. Enter it when prompted.

```sh
cd server
npm ci
printf 'Admin password: '
read -rs peng_admin_password
DEPLOY_MODE=organization ADMIN_USERNAME=admin ADMIN_PASSWORD="$peng_admin_password" COOKIE_SECURE=false PORT=0 npm start
```

| Environment variable | Behavior |
| --- | --- |
| `DEPLOY_MODE` | Defaults to `organization`. Use `local` for a credential-free workspace on loopback. |
| `PORT` | Defaults to `3000`. Use `0` for an ephemeral port. |
| `BIND_HOST` | Defaults to `127.0.0.1` in local mode and `0.0.0.0` in organization mode. Compose sets it to `0.0.0.0` inside the private Docker network. |
| `DATABASE_PATH` | Defaults to `./data/peng.sqlite3` relative to the process working directory. Mount the parent directory on a persistent, writable volume for the database and its SQLite WAL files. |
| `COOKIE_SECURE` | Defaults to `true`. Set to `false` for organization mode over plain HTTP. |
| `APP_ORIGIN` | In organization mode, set to the browser-facing origin, including the scheme and any non-default port, such as `https://reports.example.com`. The server verifies the incoming Host against this origin. When unset, the server expects an HTTP origin derived from the request Host. |
| `ADMIN_USERNAME`, `ADMIN_PASSWORD` | Required together on first startup in organization mode, including when converting from local mode. Use a randomly generated password. Bootstrap requires at least 15 characters after trimming and rejects several common values, placeholders and passwords matching the username. Once initialized, the server uses the saved credentials. |

Run `npm test` from `server/` to exercise the API and both MCP protocol modes. Tests bind to ephemeral loopback ports and use in-memory or temporary SQLite databases.

## Docker and nginx

The Compose image includes the same finding defaults and template catalog as the editor. When building a custom image, preserve the repository-relative paths of `server/`, `src/types/`, and `src/data/templates/`. Keep the backend port on the private Docker network and expose nginx to clients.

Serve the frontend and proxy the API and MCP on the same nginx origin. With an upstream Docker service named `backend`, the following locations can go in the frontend's nginx server block. For a public organization workspace, set `APP_ORIGIN` to the public HTTPS origin and keep `COOKIE_SECURE=true`.

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

Use relative URLs from the frontend. All API mutations require an exact same-origin `Origin` header, which browsers send on same-origin fetch mutations. Send that header explicitly in scripted API clients.

In organization mode, login sets a host-only, HttpOnly, SameSite=Strict session cookie scoped to `/api` that expires after seven days. Save and replay the cookie in scripted clients. Logout revokes the session. The cookie name is derived from the public origin so deployments on different local ports can coexist in the same browser. Upgrading from the old `peng_session` name or changing the public origin requires signing in again. Browsers can still send cookies to other ports on the same host.

Local mode accepts loopback hostnames and gives clients direct access to the local workspace. Login, logout, and key management return `404` in local mode.

Each server admits up to eight validly formed login attempts per connection peer and 30 total per minute, with up to two password checks in flight. The peer is the direct network connection, so clients behind the same reverse proxy share a budget. An overloaded or rate-limited login returns `429` and a `Retry-After` value in seconds.

| Method and path | Body and response |
| --- | --- |
| `GET /api/config` | `200 {mode}` in both modes. |
| `GET /api/session` | `200 {mode: 'local'}` in local mode. Organization mode returns `200 {username}` with a valid session, or `401`. |
| `POST /api/login` | JSON `{username,password}`. Returns `200 {username}` and sets the session cookie, `401` for invalid credentials, or `429` when busy or throttled. |
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

Configure the client for Streamable HTTP at the deployment's `/mcp` endpoint. For a local workspace, connect over loopback, call `list_projects` with `{}` to get `{projects: [{id, name}]}`, and add the selected `projectId` to each of the tools below. For an organization workspace, use the `Authorization: Bearer <key>` header on every request. The bearer key selects the project. The endpoint supports modern per-request MCP and legacy stateless Streamable HTTP.

- **`list_templates`** with `{}` returns the project's `templateInstructions` first, followed by a readable `reportFormat` and an empty `templates` array. For optional catalog search, pass a nonempty `query` of up to 120 characters and a `limit` from 1 to 20 (default 8). Search returns matching `id`, `title`, `category`, and `severity` summaries and `hasMore`. Both modes return `catalogAvailable`.
- **`get_template`** takes `{id}` from a search result and returns the template's category, tags, and suggested `title`, `severity`, and `cwe` defaults. Adapt those defaults to the verified finding. The default report format works with any project, including when the catalog is unavailable.
- **`append_finding`** requires `title` and a caller-generated `idempotencyKey`. It accepts an optional `severity` (defaults to `Medium`) and plain-text `description`, `poc`, `requestResponse`, `impact`, `remediation`, `notes`, `references`, `url`, `method`, `parameter`, `affectedHost`, `port`, `cve`, `cwe`, `cvss`, and `cvssVector`. It creates an `Open` finding in the selected project and returns `{findingId,created}`. Separate paragraphs with blank lines. The backend escapes the text for the HTML renderer and preserves indentation and line breaks in request and response samples.

Retry a submission with the same idempotency key and finding content. A retry returns the original finding ID and `created: false`, even after a restart, a key rotation, or deletion of that finding. Reusing a key with different content returns a tool error. Idempotency keys are scoped to each project and are removed with the project.
