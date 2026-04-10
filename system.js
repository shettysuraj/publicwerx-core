'use strict';

// publicwerx-core/system.js — Health monitoring + remote deploy for the
// PublicWerx fleet.
//
// Returns an Express router that exposes:
//   GET  /          — machine stats (CPU, memory, disk, PM2 processes)
//   POST /deploy    — run the project's deploy.sh
//
// Both routes are gated by a shared secret in the x-system-key header.
// The master dashboard at surajshetty.com/admin calls these endpoints to
// render the fleet overview and trigger remote deploys.
//
// Usage:
//   const { createSystemRoutes } = require('publicwerx-core');
//   app.use('/api/system', createSystemRoutes({
//     systemKey: process.env.SYSTEM_API_KEY,
//   }));

const os = require('os');
const { execSync, spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const express = require('express');

/**
 * @param {Object} opts
 * @param {string}  opts.systemKey                — required. Shared secret checked against x-system-key header.
 * @param {string}  [opts.deployScript='deploy.sh'] — path to deploy script, relative to projectRoot.
 * @param {string}  [opts.projectRoot]            — absolute path to project root. Defaults to 3 levels up
 *                                                   from this file's consumer (which matches the standard
 *                                                   layout: project/backend/src/index.js → project/).
 *                                                   When the consumer passes __dirname, we resolve from there.
 * @param {number}  [opts.deployTimeout=300000]   — ms before the deploy child process is killed.
 * @param {number}  [opts.maxOutputBytes=65536]   — cap on deploy stdout+stderr buffered in memory.
 * @param {Object}  [opts.backup]                 — enable backup endpoints. Omit to disable.
 * @param {string}  opts.backup.dbPath            — absolute path to the SQLite database file.
 * @param {string}  [opts.backup.dir]             — backup directory. Defaults to {projectRoot}/backups.
 * @param {number}  [opts.backup.maxBackups=14]   — max backups to keep (oldest pruned on create).
 */
function createSystemRoutes(opts = {}) {
  if (!opts.systemKey) {
    throw new Error('publicwerx-core: createSystemRoutes requires opts.systemKey');
  }

  const SYSTEM_KEY = opts.systemKey;
  const DEPLOY_TIMEOUT = opts.deployTimeout || 300000;
  const MAX_OUTPUT = opts.maxOutputBytes || 65536;
  const DEPLOY_SCRIPT = opts.deployScript || 'deploy.sh';
  const BACKUP = opts.backup || null;
  const MAX_BACKUPS = BACKUP ? (BACKUP.maxBackups || 14) : 0;

  const router = express.Router();

  // ── Auth: shared secret ─────────────────────────────────────────────────
  router.use((req, res, next) => {
    if (req.headers['x-system-key'] !== SYSTEM_KEY) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
  });

  // ── GET / — Machine stats + PM2 processes ───────────────────────────────
  // Data minimization (Tenet 5): only operational metrics, no user data.
  router.get('/', (req, res) => {
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const cpus = os.cpus();
    const loadAvg = os.loadavg();
    const mem = process.memoryUsage();

    let disk = null;
    try {
      const df = execSync('df -h / | tail -1', { timeout: 3000 }).toString().trim().split(/\s+/);
      disk = { total: df[1], used: df[2], available: df[3], usePct: df[4] };
    } catch {}

    let pm2 = [];
    try {
      const raw = execSync('pm2 jlist 2>/dev/null', { timeout: 5000 }).toString();
      const procs = JSON.parse(raw);
      pm2 = procs.map(p => ({
        name: p.name,
        status: p.pm2_env?.status,
        cpu: p.monit?.cpu,
        memory: p.monit?.memory,
        memoryMb: p.monit?.memory ? Math.round(p.monit.memory / 1024 / 1024) : 0,
        uptime: p.pm2_env?.pm_uptime ? Date.now() - p.pm2_env.pm_uptime : 0,
        restarts: p.pm2_env?.restart_time || 0,
      }));
    } catch {}

    res.json({
      features: { backup: !!BACKUP },
      host: os.hostname(),
      platform: `${os.type()} ${os.release()}`,
      nodeVersion: process.version,
      uptime: {
        system: Math.floor(os.uptime()),
        process: Math.floor(process.uptime()),
      },
      cpu: {
        cores: cpus.length,
        model: cpus[0]?.model,
        loadAvg: {
          '1m': loadAvg[0]?.toFixed(2),
          '5m': loadAvg[1]?.toFixed(2),
          '15m': loadAvg[2]?.toFixed(2),
        },
      },
      memory: {
        total: Math.round(totalMem / 1024 / 1024),
        free: Math.round(freeMem / 1024 / 1024),
        used: Math.round((totalMem - freeMem) / 1024 / 1024),
        usePct: ((1 - freeMem / totalMem) * 100).toFixed(1),
        processRss: Math.round(mem.rss / 1024 / 1024),
        processHeap: Math.round(mem.heapUsed / 1024 / 1024),
      },
      disk,
      pm2,
    });
  });

  // ── POST /deploy — Run the project's deploy script ──────────────────────
  router.post('/deploy', (req, res) => {
    // Resolve project root from the caller's perspective. If the consumer
    // passed projectRoot, use it; otherwise assume standard layout where
    // this middleware is mounted from project/backend/src/index.js (3 up).
    const projectRoot = opts.projectRoot
      ? path.resolve(opts.projectRoot)
      : path.resolve(process.cwd());
    const script = path.join(projectRoot, DEPLOY_SCRIPT);

    if (!fs.existsSync(script)) {
      return res.status(500).json({ error: `${DEPLOY_SCRIPT} not found at ${projectRoot}` });
    }

    let output = '';
    const append = (chunk) => {
      if (output.length < MAX_OUTPUT) {
        output += chunk.toString().slice(0, MAX_OUTPUT - output.length);
      }
    };

    const child = spawn('bash', [script], {
      cwd: projectRoot,
      timeout: DEPLOY_TIMEOUT,
      env: { ...process.env, PATH: process.env.PATH },
    });

    child.stdout.on('data', append);
    child.stderr.on('data', append);

    child.on('close', code => {
      res.json({ ok: code === 0, exitCode: code, output });
    });

    child.on('error', err => {
      res.status(500).json({ error: err.message, output });
    });
  });

  // ── Backup routes (opt-in) ───────────────────────────────────────────────
  if (BACKUP) {
    const backupDir = BACKUP.dir
      || path.join(opts.projectRoot ? path.resolve(opts.projectRoot) : process.cwd(), 'backups');

    // GET /backups — list available backups
    router.get('/backups', (req, res) => {
      try {
        if (!fs.existsSync(backupDir)) return res.json([]);
        const files = fs.readdirSync(backupDir)
          .filter(f => f.endsWith('.db.gz'))
          .map(f => {
            const stat = fs.statSync(path.join(backupDir, f));
            return { filename: f, size: stat.size, created: stat.mtime.toISOString() };
          })
          .sort((a, b) => b.created.localeCompare(a.created));
        res.json(files);
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // POST /backups — create a new backup
    router.post('/backups', (req, res) => {
      try {
        if (!fs.existsSync(BACKUP.dbPath)) {
          return res.status(500).json({ error: 'Database not found' });
        }
        fs.mkdirSync(backupDir, { recursive: true });

        const stamp = new Date().toISOString().replace(/[-:]/g, '').replace('T', '_').slice(0, 15);
        const backupFile = path.join(backupDir, `backup_${stamp}.db`);

        // VACUUM INTO creates a consistent WAL-safe snapshot
        const Database = require('better-sqlite3');
        const db = new Database(BACKUP.dbPath, { readonly: true });
        db.exec(`VACUUM INTO '${backupFile.replace(/'/g, "''")}'`);
        db.close();

        // Compress
        const { execSync: ex } = require('child_process');
        ex(`gzip "${backupFile}"`, { timeout: 30000 });

        const gzFile = `backup_${stamp}.db.gz`;
        const stat = fs.statSync(path.join(backupDir, gzFile));

        // Prune oldest if over limit
        const all = fs.readdirSync(backupDir)
          .filter(f => f.endsWith('.db.gz'))
          .sort();
        while (all.length > MAX_BACKUPS) {
          fs.unlinkSync(path.join(backupDir, all.shift()));
        }

        res.json({ ok: true, filename: gzFile, size: stat.size });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // DELETE /backups/:filename — remove a specific backup
    router.delete('/backups/:filename', (req, res) => {
      const filename = path.basename(req.params.filename);
      if (!filename.endsWith('.db.gz')) {
        return res.status(400).json({ error: 'Invalid filename' });
      }
      const filePath = path.join(backupDir, filename);
      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'Backup not found' });
      }
      try {
        fs.unlinkSync(filePath);
        res.json({ ok: true });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });
  }

  return router;
}

module.exports = { createSystemRoutes };
