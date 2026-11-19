# Peng backend

The backend serves the browser API and the Streamable HTTP MCP endpoint on one port. It uses a file-backed SQLite database and can search the app's template catalog when the frontend sources are present.

## Run

Use Node.js 22 or later. From the repository root, start a credential-free local workspace on an ephemeral loopback port.

```sh
cd server
npm ci
DEPLOY_MODE=local PORT=0 npm start
```

For an organization deployment, generate and save a password with `openssl rand -hex 24`. For testing organization mode over loopback HTTP, enter the saved password when prompted.

```sh
printf 'Admin password: '
read -rs peng_admin_password
BIND_HOST=127.0.0.1 ADMIN_USERNAME=admin ADMIN_PASSWORD="$peng_admin_password" COOKIE_SECURE=false PORT=0 npm start
```

| Environment variable | Behavior |
| --- | --- |
| `DEPLOY_MODE` | `organization` (default) or `local`. Startup rejects other values. |
| `PORT` | Defaults to `3000`. Use `0` for an ephemeral port. |
| `BIND_HOST` | Defaults to `127.0.0.1` in local mode and `0.0.0.0` in organization mode. For a local-mode backend behind a container proxy, set `BIND_HOST=0.0.0.0` on the private network and publish only the proxy on loopback. |
| `DATABASE_PATH` | Defaults to `./data/peng.sqlite3` relative to the process working directory. Mount the parent directory on a persistent, writable volume for the database and its SQLite WAL files. |
| `COOKIE_SECURE` | Defaults to `true`. Set to `false` for plain HTTP when testing organization mode. |
| `APP_ORIGIN` | Set to the client-facing origin, including the scheme and any non-default port, such as `https://reports.example.com`. The incoming Host must match the configured authority. When unset, the expected origin is HTTP and derived from Host. In local mode that Host must be `localhost`, an IPv4 loopback address, or `[::1]`, with an optional port. The server ignores forwarded Host headers. |
| `ADMIN_USERNAME`, `ADMIN_PASSWORD` | Used only in organization mode. Required together to initialize an empty database or promote a local workspace without a primary admin. Bootstrap requires at least 15 characters after trimming and rejects several common values, placeholders and passwords matching the username. Later startups can omit both variables and keep the saved credentials. |

Run `npm test` from `server/` to exercise the API and both MCP protocol modes. Tests bind to ephemeral loopback ports and use in-memory or temporary SQLite databases.

## SQLite workspace and mode changes

Stop the backend before switching modes and reuse the same database volume. A fresh local database stores projects and findings under a workspace owner with no login. The first organization startup promotes that owner in place using the provided admin credentials. Projects, findings, template instructions, and MCP idempotency records stay attached to the same owner.

On a database initialized in organization mode, local mode exposes the primary admin's workspace. For existing databases created before deploy modes, the primary admin is the earliest user by SQLite ID, matching the original bootstrap order. Other owners' records remain private to their organization accounts. Local requests ignore existing session cookies and bearer keys. Saved organization credentials, sessions, and keys can be used again in organization mode subject to their usual validity checks.

Local mode gives everyone with network access to the allowed Host full access to the shared workspace. Keep the backend and any public-facing proxy bound to loopback or behind a trusted private access boundary. Host and browser origin checks protect against browser requests from other sites. Native clients can set their own headers.

## Docker and nginx

The Compose image includes the same finding defaults and template catalog as the editor. When building a custom image, preserve the repository-relative paths of `server/`, `src/types/`, and `src/data/templates/`. Keep the backend port on the private Docker network and expose nginx to clients.

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

Use relative URLs from the frontend. All API mutations in both modes require an exact same-origin `Origin` header, which browsers send on same-origin fetch mutations. Send that header explicitly in scripted API clients. Local mode also rejects mismatched Origin headers on reads and browser Fetch Metadata that identifies a request from another origin.

In organization mode login sets a host-only, HttpOnly, SameSite=Strict session cookie scoped to `/api` that expires after seven days. Logout revokes the session. In local mode project and finding routes use the shared workspace. Login, logout, and key management return `404` and set no cookies.

Save and replay the cookie returned by login. Its name is derived from the public origin so deployments on different local ports can coexist in the same browser. Upgrading from the old `peng_session` name or changing the public origin requires signing in again. Browsers can still send cookies to other ports on the same host.

Each server admits up to eight validly formed login attempts per connection peer and 30 total per minute, with up to two password checks in flight. The peer is the direct network connection, so clients behind the same reverse proxy share a budget. An overloaded or rate-limited login returns `429` and a `Retry-After` value in seconds.

| Method and path | Body and response |
| --- | --- |
| `GET /api/config` | Public `200 {mode}` in both modes. |
| `GET /api/session` | Local mode returns `200 {mode:"local"}`. Organization mode returns `200 {username,mode:"organization"}` with a valid session or `401`. |
| `POST /api/login` | JSON `{username,password}`. Returns `200 {username}` and sets the session cookie, `401` for invalid credentials, or `429` when busy or throttled. |
| `POST /api/logout` | `204` and clears the session cookie. |
| `GET /api/projects` | Array of the current workspace's projects. |
| `PUT /api/projects/:id` | Upserts the full app `Project`. Returns `204`. Omit optional `templateInstructions` to keep the saved value or send an empty string to clear it. |
| `DELETE /api/projects/:id` | Deletes the project, findings and keys. Returns `204`. |
| `GET /api/projects/:id/findings` | Array of findings for the project. |
| `PUT /api/projects/:id/findings/:findingId` | Upserts one full app `Finding`. Returns `204`. |
| `DELETE /api/projects/:id/findings/:findingId` | Deletes one finding. Returns `204`. |
| `GET /api/projects/:id/keys` | Array of `{id,name,createdAt,access}` records with ISO 8601 timestamps. |
| `POST /api/projects/:id/keys` | JSON `{name,access?}`. Choose `append` (default) for submission or `manage` for reading and triage as well. Returns `201 {key}`. Copy the bearer key at creation. SQLite stores its SHA-256 digest. |
| `DELETE /api/projects/:id/keys/:keyId` | Revokes a key immediately. Returns `204`. |

Project and finding IDs in PUT bodies must match the path. The browser API preserves rich text fields used by the app editor.

## MCP

The endpoint supports modern per-request MCP and legacy stateless Streamable HTTP. In organization mode, configure the client for Streamable HTTP at the deployment's `/mcp` URL with `Authorization: Bearer <key>` on every request. The key selects a single project.

In local mode, use the same endpoint without credentials. Call `list_projects` with `{}` to get project IDs, names and finding counts for the shared workspace. Pass one of those IDs as `projectId` to project-specific tools. You can omit `projectId` when there is exactly one project. With multiple projects, an explicit ID is required even when names differ. An unknown ID or empty workspace returns a tool error.

Local MCP validates any supplied Origin and rejects browser requests marked as coming from another origin. Browser MCP mutations must send the exact same-origin `Origin` header. Native clients can omit Origin and send MCP POST requests as `application/json`.

### Submission and triage

1. Call `list_templates` to read project instructions, the report format and the first page of the catalog. Use `limit` and `offset` to browse further, or narrow the results with `category` and `query`. Call `get_template` with a result ID for defaults, remediation guidance and references.
2. Submit one report card with `append_finding` or up to 25 cards in one `append_findings` call (256 KiB request limit). Give each card its own stable `idempotencyKey`. Check every batch result before retrying. Use `templateId` to associate a card with its source template. Supply explicit values for the fields you need to override.
3. To resume in a later session, call `list_findings` with a text query or a severity/status filter. It returns summaries and IDs. Use `limit`, `offset` and `hasMore` to page through matches, then call `get_finding` with the ID to read the full record. Rich-text fields in the returned record are stored HTML; submit plain text when editing them.
4. Use `update_finding` with `id` and a partial `patch`. For example, `{"id":"<finding-id>","patch":{"status":"False Positive","triageNotes":"Confirmed during owner review."}}`. In local mode include `projectId` when multiple projects exist. In organization mode the project comes from the key. Reading and updating require a key issued with `manage` access. Existing submission keys retain their original permissions.

New cards start with status `New`. Existing `Open` records keep that status. Other choices are `Verified`, `False Positive`, `Duplicate`, `Accepted Risk` and `Fixed`. Use `confidence` for certainty independently of severity. Record multiple affected endpoints in `targets` and evidence paths or URLs in `evidence`. The reporting service stores those references as text.

The MCP tool schemas expose accepted fields, enum values and length limits. Invalid values and unknown project, template or finding IDs return errors. Split large batches to fit the HTTP request limit.

Retry a submission with the same idempotency key and finding content. A retry returns the original finding ID and `created: false`, even after a restart, a key rotation, or deletion of that finding. Reusing a key with different content returns a tool error. Idempotency keys are scoped to each project and are removed with the project.
