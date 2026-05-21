'use strict';

// Process-level safety net for unhandled async errors.
//
// Express 4 does not catch promise rejections that escape async route handlers.
// Node's default behavior for unhandledRejection is termination, which means
// one forgotten .catch() takes the whole process down. This module installs
// listeners that log the error and invoke an optional onError callback (for
// OTel span recording, alerting, etc.) but do NOT exit.
//
// Usage:
//   const { installCrashGuard } = require('publicwerx-core');
//   installCrashGuard({
//     onError: (kind, err) => {
//       // optional: record to OTel, fire alert, etc.
//     },
//   });
//
// Tradeoff: this can mask real bugs (a degraded request that should have
// crashed loudly instead persists). The fleet stance: a 500 response is
// preferable to a process exit. Errors are logged loudly to stderr so they
// remain discoverable via pm2 logs / app_logs / Honeycomb.
//
// Idempotent — safe to call multiple times; only the first call installs.

let installed = false;

function installCrashGuard(opts = {}) {
  if (installed) return;
  installed = true;

  const onError = typeof opts.onError === 'function' ? opts.onError : null;

  function invoke(kind, raw) {
    const err = raw instanceof Error ? raw : new Error(String(raw));
    // Loud stderr log — survives container restarts, picked up by pm2/syslog.
    console.error(`[crash-guard:${kind}]`, err.stack || err.message);
    if (onError) {
      try { onError(kind, err); } catch (cbErr) {
        // The error callback itself failed. Log and continue — we cannot
        // afford recursion here.
        console.error('[crash-guard:onError-failed]', cbErr?.message);
      }
    }
  }

  process.on('unhandledRejection', (reason) => invoke('unhandledRejection', reason));
  process.on('uncaughtException', (err) => invoke('uncaughtException', err));
}

module.exports = { installCrashGuard };
