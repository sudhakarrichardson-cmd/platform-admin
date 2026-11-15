# Instructions for AI coding agents

This repository is the **PlotFarms Platform Admin** service — the
shared user-management layer that sits on top of the self-hosted
Supabase stack and serves all PlotFarms apps (textiles, pa, etc.).

It runs at db.plotfarms.com/admin and at the /admin path of each app
domain, acting as the single place where app admins and their employees
are created, granted roles, and disabled.

## Map

| Path | What |
|---|---|
| `services/platform-admin/src/server.js` | HTTP server — platform surface (/admin, /api/platform/*) and per-app surface (/api/app/*); GoTrue proxy; role grant logic |
| `services/platform-admin/src/access.html` | Admin web UI (served from both surfaces) |
| `services/platform-admin/.env.example` | Configuration template |

## Conventions

- Plain Node 20, CommonJS, no framework, no build step. Only dependency: `pg`.
- Two surfaces on a single process, distinguished by the `Host` header:
  - **Platform surface** (`PLATFORM_HOST`, e.g. db.plotfarms.com) — sign-in
    with the Supabase dashboard credentials; manages all apps.
  - **App surface** (each app's own domain) — sign-in with the app's
    admin JWT; manages only that app's users. Apps forward their
    `/api/app/*` calls here; they hold no Auth service key themselves.
- `rolesForApp` reads `<schema>.role_capabilities` for the requesting
  app: a role with `manage_users` may add/disable people but never
  touch the app admin, and never assign roles above its own capability.
- Every change is audited in `platform.access_audit`.
- No secrets in code or this file. Configuration comes from `.env` only
  (see `.env.example`). The `.env` is never committed.

## App registration

Each app that uses platform-admin must have a row in `platform.apps`
(added by its own schema migration) with:
- `app_code` — short key matching `APP_CODE` in that app's auth module
- `schema_name` — the Postgres schema the app owns
- `domain` — the app's public domain (used to match the Host header)
- `admin_role_code` — the role code that platform-admin grants the owner

Each app's DB role also needs `BYPASSRLS` to read `platform.user_app_access`.

## Verifying changes

```bash
node services/platform-admin/src/server.js
```

No automated test suite yet — manual smoke test via the admin UI and
the /api/platform/overview endpoint.
