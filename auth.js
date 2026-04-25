'use strict';

// publicwerx-core/auth.js — RS256 auth middleware for the PublicWerx fleet.
//
// All identity is owned by auth.surajshetty.com. Consumer apps verify access
// tokens locally using the auth service's RS256 public key (fetched once and
// cached). This module extracts the copy-pasted verification + middleware
// logic that was identical across njordfellfutures, peerlinq, gottapickone,
// and srj1cc.
//
// Usage:
//   const { createAuthMiddleware } = require('publicwerx-core');
//   const auth = createAuthMiddleware({
//     superAdminEmail: process.env.SUPER_ADMIN_EMAIL,
//     onUser: (userId, email) => db.ensureLocalUser(userId, email),
//   });
//   app.get('/api/me', auth.requireAuth, handler);
//   app.use('/api/admin', auth.requireAdmin, adminRoutes);

const jwt = require('jsonwebtoken');

/**
 * @param {Object} opts
 * @param {string}   [opts.authServiceUrl='https://auth.surajshetty.com']
 * @param {string}   [opts.issuer='auth.surajshetty.com']
 * @param {string}   [opts.superAdminEmail]  — lowercase. If unset, requireAdmin always 403s.
 * @param {Function} [opts.onUser]           — (userId, email) => void. Called on successful
 *                                              requireAuth/optionalAuth for lazy user creation.
 *                                              NOT called by requireAdmin (by design — see
 *                                              project_gpo_admin_gate.md).
 */
function createAuthMiddleware(opts = {}) {
  const AUTH_SERVICE_URL = opts.authServiceUrl || 'https://auth.surajshetty.com';
  const AUTH_SERVICE_ISSUER = opts.issuer || 'auth.surajshetty.com';
  const SUPER_ADMIN_EMAIL = (opts.superAdminEmail || '').toLowerCase();
  const onUser = typeof opts.onUser === 'function' ? opts.onUser : null;

  // ── Public key cache ────────────────────────────────────────────────────
  // Single in-flight promise. On fetch failure the cache is invalidated so
  // the next request retries. Successful fetches are cached for the process
  // lifetime (the key only changes on a rotation, which is a coordinated
  // restart event anyway).
  let publicKeyPromise = null;

  function getAuthPublicKey() {
    if (!publicKeyPromise) {
      publicKeyPromise = (async () => {
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), 5000);
        try {
          const r = await fetch(`${AUTH_SERVICE_URL}/auth/public-key`, { signal: ctrl.signal });
          if (!r.ok) throw new Error(`public-key fetch ${r.status}`);
          const { publicKey } = await r.json();
          if (!publicKey) throw new Error('public-key missing from response');
          return publicKey;
        } finally {
          clearTimeout(t);
        }
      })().catch(err => {
        publicKeyPromise = null;
        throw err;
      });
    }
    return publicKeyPromise;
  }

  async function verifyAuthToken(token) {
    const publicKey = await getAuthPublicKey();
    return jwt.verify(token, publicKey, {
      algorithms: ['RS256'],
      issuer: AUTH_SERVICE_ISSUER,
    });
  }

  // ── Internal: extract + verify Bearer token ─────────────────────────────
  async function extractBearer(req) {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return { ok: false, status: 401, error: 'Login required' };

    let payload;
    try {
      payload = await verifyAuthToken(token);
    } catch {
      return { ok: false, status: 401, error: 'Invalid or expired token' };
    }

    if (!payload.sub) {
      return { ok: false, status: 401, error: 'Invalid token payload' };
    }
    const email = payload.email ? payload.email.toLowerCase() : null;

    return { ok: true, userId: payload.sub, email };
  }

  // ── Middleware: requireAuth ──────────────────────────────────────────────
  // Verifies Bearer token, attaches req.user = { userId, email }, calls
  // onUser() for lazy local user creation.
  async function requireAuth(req, res, next) {
    try {
      const r = await extractBearer(req);
      if (!r.ok) return res.status(r.status).json({ error: r.error });
      req.user = { userId: r.userId, email: r.email };
      if (onUser) onUser(r.userId, r.email);
      next();
    } catch (err) {
      console.error('[publicwerx-core:auth] middleware error:', err.message);
      res.status(500).json({ error: 'Internal error' });
    }
  }

  // ── Middleware: optionalAuth ─────────────────────────────────────────────
  // Same as requireAuth but continues without error if no token is present
  // or if the token is invalid. req.user is set only on success.
  async function optionalAuth(req, res, next) {
    try {
      const r = await extractBearer(req);
      if (r.ok) {
        req.user = { userId: r.userId, email: r.email };
        if (onUser) onUser(r.userId, r.email);
      }
    } catch {
      // swallow — optional means optional
    }
    next();
  }

  // ── Middleware: requireAdmin ─────────────────────────────────────────────
  // Verifies the JWT directly (does NOT reuse requireAuth) and does NOT call
  // onUser. An attacker hitting /api/admin/* with a valid non-admin token
  // would otherwise get a player row created even though the endpoint 403s.
  // Single-source exact-email-match against superAdminEmail.
  async function requireAdmin(req, res, next) {
    try {
      if (!SUPER_ADMIN_EMAIL) {
        return res.status(403).json({ error: 'Admin not configured' });
      }
      const r = await extractBearer(req);
      if (!r.ok) return res.status(r.status).json({ error: r.error });
      if (!r.email || r.email !== SUPER_ADMIN_EMAIL) {
        return res.status(403).json({ error: 'Admin access required' });
      }
      req.user = { userId: r.userId, email: r.email };
      next();
    } catch (err) {
      console.error('[publicwerx-core:admin] middleware error:', err.message);
      res.status(500).json({ error: 'Internal error' });
    }
  }

  return {
    requireAuth,
    optionalAuth,
    requireAdmin,
    // Exposed for advanced use (e.g. Socket.IO handshake verification)
    verifyAuthToken,
    getAuthPublicKey,
  };
}

module.exports = { createAuthMiddleware };
