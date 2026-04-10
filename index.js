'use strict';

// publicwerx-core — Shared chassis for PublicWerx projects.
//
// Install from git:
//   npm install github:shettysuraj/publicwerx-core
//
// Quick start:
//   const { createAuthMiddleware, createSystemRoutes } = require('publicwerx-core');
//
//   const auth = createAuthMiddleware({
//     superAdminEmail: process.env.SUPER_ADMIN_EMAIL,
//     onUser: (userId, email) => db.ensureLocalUser(userId, email),
//   });
//
//   app.use('/api/system', createSystemRoutes({
//     systemKey: process.env.SYSTEM_API_KEY,
//   }));
//
//   app.get('/api/me', auth.requireAuth, (req, res) => { ... });

const { createAuthMiddleware } = require('./auth');
const { createSystemRoutes } = require('./system');

module.exports = { createAuthMiddleware, createSystemRoutes };
