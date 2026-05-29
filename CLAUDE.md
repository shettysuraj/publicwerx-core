# publicwerx-core

Shared chassis (npm package) for PublicWerx projects. Consumed by the fleet's Express apps; not a deployed service itself.

## What it provides

- **`createAuthMiddleware`** — RS256 JWT verification against auth.publicwerx.org (`requireAuth`, `requireAdmin`). Extracts `req.user` incl. `sub_apps` claim.
- **`isSubscribed(user, appId)`** — subscription check from the JWT `sub_apps` claim (`"all"`, an array, or absent).
- **`createSystemRoutes`** — `/api/system` health + backup routes (shared `SYSTEM_API_KEY`).
- **`installCrashGuard`** — process-level safety net for unhandled async errors (logs + OTel span instead of exiting).
- **`createCronRunner` / `dailyAtUtc` / `weeklyAtUtc`** — self-healing in-process scheduler with persistent last-run timestamps (replaces fragile `setInterval` crons).

## Stack

- Plain Node CommonJS library. Entry: `index.js`. Modules: `auth.js`, `system.js`, `crash-guard.js`, `cron.js`.
- Current version: 1.7.0.

## Key conventions

- **`files` allowlist in package.json is load-bearing.** Any new `.js` added to the lib MUST be listed in the `files` array, or consumers' `npm ci` silently omits it and they crash at boot.
- **Bump the version on every change** that consumers need to pick up; consumers then bump their lockfile (`npm ci`, never `npm install`) and redeploy.
- Auth is a critical dependency — auth.publicwerx.org down = fleet-wide stop-the-world by design. Do not add "ride out auth outage" caching.

## Consumers

aapta, samanu (Group A — JWT-only enforcement), plus Group B/hybrid apps that sync tier locally. See each app's CLAUDE.md.
