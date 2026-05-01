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
const crypto = require('crypto');
const { execSync, execFileSync, spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const express = require('express');

// ── Lean S3 upload — zero deps, just crypto + fetch ──────────────────────
// AWS Signature Version 4 signing for S3 PUT, using EC2 instance role creds.

const S3_REGION = 'us-east-1';

function hmacSha256(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest();
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/** Fetch temporary credentials from EC2 Instance Metadata Service (IMDSv2). */
async function getInstanceCredentials() {
  // Step 1: get a session token
  const tokenRes = await fetch('http://169.254.169.254/latest/api/token', {
    method: 'PUT',
    headers: { 'X-aws-ec2-metadata-token-ttl-seconds': '60' },
  });
  const token = await tokenRes.text();

  // Step 2: get the role name
  const roleRes = await fetch(
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    { headers: { 'X-aws-ec2-metadata-token': token } },
  );
  const role = (await roleRes.text()).trim();

  // Step 3: get credentials for the role
  const credRes = await fetch(
    `http://169.254.169.254/latest/meta-data/iam/security-credentials/${role}`,
    { headers: { 'X-aws-ec2-metadata-token': token } },
  );
  return credRes.json();
}

/** Upload a buffer to S3 using a signed PUT request. */
async function s3Put(bucket, key, body) {
  const creds = await getInstanceCredentials();
  const host = `${bucket}.s3.${S3_REGION}.amazonaws.com`;
  const now = new Date();
  const dateStamp = now.toISOString().replace(/[-:]/g, '').slice(0, 8);        // YYYYMMDD
  const amzDate = now.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z/, 'Z'); // YYYYMMDDTHHmmssZ
  const payloadHash = sha256Hex(body);

  const headers = {
    Host: host,
    'x-amz-date': amzDate,
    'x-amz-content-sha256': payloadHash,
    'Content-Length': String(body.length),
  };
  // If using temporary credentials (instance role), include the session token
  if (creds.Token) headers['x-amz-security-token'] = creds.Token;

  // Canonical request
  const sortedEntries = Object.entries(headers).sort(([a],[b]) => a.toLowerCase().localeCompare(b.toLowerCase()));
  const canonHeaders = sortedEntries.map(([k,v]) => `${k.toLowerCase()}:${v}`).join('\n') + '\n';
  const signedHeaders = sortedEntries.map(([k]) => k.toLowerCase()).join(';');

  const canonicalRequest = [
    'PUT',
    `/${key}`,
    '',  // no query string
    canonHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  // String to sign
  const scope = `${dateStamp}/${S3_REGION}/s3/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    scope,
    sha256Hex(canonicalRequest),
  ].join('\n');

  // Signing key
  let sigKey = hmacSha256(`AWS4${creds.SecretAccessKey}`, dateStamp);
  sigKey = hmacSha256(sigKey, S3_REGION);
  sigKey = hmacSha256(sigKey, 's3');
  sigKey = hmacSha256(sigKey, 'aws4_request');

  const signature = hmacSha256(sigKey, stringToSign).toString('hex');
  const authorization = `AWS4-HMAC-SHA256 Credential=${creds.AccessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const res = await fetch(`https://${host}/${key}`, {
    method: 'PUT',
    headers: { ...headers, Authorization: authorization },
    body,
  });

  if (!res.ok) {
    const errBody = await res.text();
    throw new Error(`S3 PUT failed (${res.status}): ${errBody}`);
  }
  return { bucket, key };
}

/**
 * @param {Object} opts
 * @param {string}  opts.systemKey                — required. Shared secret checked against x-system-key header.
 * @param {string}  [opts.deployScript='deploy.sh'] — path to deploy script, relative to projectRoot.
 * @param {string}  [opts.projectRoot]            — absolute path to project root. Defaults to 3 levels up
 *                                                   from this file's consumer (which matches the standard
 *                                                   layout: project/backend/src/index.js → project/).
 *                                                   When the consumer passes __dirname, we resolve from there.
 * @param {number}  [opts.deployTimeout=300000]   — ms before SIGTERM is sent to the deploy process.
 *                                                   SIGKILL follows 10s later if it's still alive.
 * @param {number}  [opts.maxOutputBytes=65536]   — cap on deploy stdout+stderr buffered in memory.
 * @param {Function} [opts.onDeploy]              — optional callback({ event, ip, userAgent, exitCode,
 *                                                   durationMs, outputBytes, truncated }). Called on
 *                                                   deploy_started, deploy_completed, deploy_failed.
 *                                                   Use for audit logging.
 * @param {Object}  [opts.backup]                 — enable backup endpoints. Omit to disable.
 * @param {string}  opts.backup.dbPath            — absolute path to the SQLite database file.
 * @param {string}  opts.backup.label             — backup filename prefix, e.g. 'peerlinq.org_db'.
 * @param {string}  [opts.backup.dir]             — backup directory. Defaults to {projectRoot}/backups.
 * @param {number}  [opts.backup.maxBackups=14]   — max backups to keep (oldest pruned on create).
 * @param {string}  [opts.backup.s3Bucket]        — S3 bucket name. If set, backups are also uploaded
 *                                                   to s3://{bucket}/backups/{label}/{filename}.
 *                                                   Uses EC2 IAM instance role credentials (IMDSv2).
 * @param {Object}  [opts.health]                 — configure the GET /health verdict endpoint.
 * @param {string}  [opts.health.serviceName]     — service identifier in health response (default: hostname).
 * @param {Object}  [opts.health.sqlite]          — better-sqlite3 Database instance. Runs read + integrity check.
 * @param {boolean} [opts.health.s3]              — if true, verifies IMDSv2 credentials are available.
 * @param {string[]} [opts.health.ssl]            — domain names to check SSL certificate expiry.
 * @param {string}  [opts.health.authUrl]         — auth service URL to probe (omit for the auth service itself).
 * @param {Object}  [opts.health.custom]          — map of name → async function returning { status: 'pass'|'warn'|'fail', ... }.
 */
function createSystemRoutes(opts = {}) {
  if (!opts.systemKey) {
    throw new Error('publicwerx-core: createSystemRoutes requires opts.systemKey');
  }

  const SYSTEM_KEY = opts.systemKey;
  const DEPLOY_TIMEOUT = opts.deployTimeout || 300000;
  const SIGKILL_GRACE = 10000;
  const MAX_OUTPUT = opts.maxOutputBytes || 65536;
  const DEPLOY_SCRIPT = opts.deployScript || 'deploy.sh';
  const BACKUP = opts.backup || null;
  const MAX_BACKUPS = BACKUP ? (BACKUP.maxBackups || 14) : 0;
  const onDeploy = typeof opts.onDeploy === 'function' ? opts.onDeploy : null;

  let deployInFlight = false;

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
  // Single-flight: rejects concurrent deploys with 409.
  // Two-stage kill: SIGTERM at timeout, SIGKILL 10s later (bash doesn't
  // reliably propagate signals to long-running children like npm ci).
  router.post('/deploy', (req, res) => {
    if (deployInFlight) {
      return res.status(409).json({ error: 'Deploy already in progress' });
    }

    const projectRoot = opts.projectRoot
      ? path.resolve(opts.projectRoot)
      : path.resolve(process.cwd());
    const script = path.join(projectRoot, DEPLOY_SCRIPT);

    if (!fs.existsSync(script)) {
      return res.status(500).json({ error: `${DEPLOY_SCRIPT} not found at ${projectRoot}` });
    }

    deployInFlight = true;
    const startedAt = Date.now();
    const callerIp = req.ip || null;
    const userAgent = (req.get('user-agent') || '').slice(0, 512) || null;

    if (onDeploy) onDeploy({ event: 'deploy_started', ip: callerIp, userAgent });

    const chunks = [];
    let outputBytes = 0;
    let truncated = false;
    const appendOutput = (buf) => {
      if (truncated) return;
      const remaining = MAX_OUTPUT - outputBytes;
      if (buf.length <= remaining) {
        chunks.push(buf);
        outputBytes += buf.length;
        return;
      }
      if (remaining > 0) {
        chunks.push(buf.subarray(0, remaining));
        outputBytes += remaining;
      }
      truncated = true;
    };

    const child = spawn('bash', [script], {
      cwd: projectRoot,
      env: { ...process.env, PATH: process.env.PATH },
    });

    child.stdout.on('data', appendOutput);
    child.stderr.on('data', appendOutput);

    let responded = false;
    const finish = (fn) => {
      if (responded) return;
      responded = true;
      deployInFlight = false;
      if (sigtermTimer) clearTimeout(sigtermTimer);
      if (sigkillTimer) clearTimeout(sigkillTimer);
      fn();
    };

    // Two-stage kill: SIGTERM at deadline, SIGKILL after grace period
    let sigkillTimer = null;
    const sigtermTimer = setTimeout(() => {
      try { child.kill('SIGTERM'); } catch {}
      sigkillTimer = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch {}
      }, SIGKILL_GRACE);
    }, DEPLOY_TIMEOUT);

    child.on('close', (code) => {
      finish(() => {
        const output = Buffer.concat(chunks).toString('utf8')
          + (truncated ? '\n[output truncated at 64KB]' : '');
        const durationMs = Date.now() - startedAt;
        if (onDeploy) onDeploy({
          event: code === 0 ? 'deploy_completed' : 'deploy_failed',
          ip: callerIp, userAgent, exitCode: code,
          durationMs, outputBytes, truncated,
        });
        res.json({ ok: code === 0, exitCode: code, output, truncated });
      });
    });

    child.on('error', (err) => {
      finish(() => {
        if (onDeploy) onDeploy({
          event: 'deploy_failed', ip: callerIp, userAgent,
          error: err.message, durationMs: Date.now() - startedAt,
        });
        res.status(500).json({ error: err.message });
      });
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
    router.post('/backups', async (req, res) => {
      try {
        if (!fs.existsSync(BACKUP.dbPath)) {
          return res.status(500).json({ error: 'Database not found' });
        }
        fs.mkdirSync(backupDir, { recursive: true });

        const stamp = new Date().toISOString().replace(/[-:]/g, '').replace('T', '_').slice(0, 15);
        const label = BACKUP.label || 'backup';
        const backupFile = path.join(backupDir, `${label}_${stamp}.db`);

        // VACUUM INTO creates a consistent WAL-safe snapshot
        const Database = require('better-sqlite3');
        const db = new Database(BACKUP.dbPath, { readonly: true });
        db.exec(`VACUUM INTO '${backupFile.replace(/'/g, "''")}'`);
        db.close();

        // Compress
        execFileSync('gzip', [backupFile], { timeout: 30000 });

        const gzFile = `${label}_${stamp}.db.gz`;
        const gzPath = path.join(backupDir, gzFile);
        const stat = fs.statSync(gzPath);

        // Upload to S3 if configured (best-effort, don't fail the backup)
        let s3 = null;
        if (BACKUP.s3Bucket) {
          try {
            const s3Key = `backups/${label}/${gzFile}`;
            const result = await s3Put(BACKUP.s3Bucket, s3Key, fs.readFileSync(gzPath));
            s3 = result;
          } catch (s3Err) {
            console.error('[publicwerx-core:backup] S3 upload failed:', s3Err.message);
            s3 = { error: s3Err.message };
          }
        }

        // Prune oldest if over limit
        const all = fs.readdirSync(backupDir)
          .filter(f => f.endsWith('.db.gz'))
          .sort();
        while (all.length > MAX_BACKUPS) {
          fs.unlinkSync(path.join(backupDir, all.shift()));
        }

        res.json({ ok: true, filename: gzFile, size: stat.size, s3 });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // POST /backups/restore — restore a backup (stops app, swaps DB, restarts)
    router.post('/backups/restore', (req, res) => {
      const { filename } = req.body || {};
      if (!filename || !filename.endsWith('.db.gz')) {
        return res.status(400).json({ error: 'filename required (must end in .db.gz)' });
      }
      const safeName = path.basename(filename);
      const backupPath = path.join(backupDir, safeName);
      if (!fs.existsSync(backupPath)) {
        return res.status(404).json({ error: 'Backup not found' });
      }
      try {
        // 1. Safety: create a pre-restore backup of the current DB
        const stamp = new Date().toISOString().replace(/[-:]/g, '').replace('T', '_').slice(0, 15);
        const label = BACKUP.label || 'backup';
        const preRestoreName = `${label}_pre_restore_${stamp}.db`;
        const preRestorePath = path.join(backupDir, preRestoreName);
        fs.copyFileSync(BACKUP.dbPath, preRestorePath);
        execFileSync('gzip', [preRestorePath], { timeout: 30000 });

        // 2. Decompress the selected backup to a temp file
        const tmpRestore = path.join(backupDir, '_restore_tmp.db');
        execSync(`gunzip -c "${backupPath}" > "${tmpRestore}"`, { timeout: 30000 });

        // 3. Validate the restored file is a valid SQLite DB
        const Database = require('better-sqlite3');
        const testDb = new Database(tmpRestore, { readonly: true });
        testDb.prepare('SELECT 1').get(); // throws if corrupt
        testDb.close();

        // 4. Remove WAL/SHM files and swap the DB
        const walPath = BACKUP.dbPath + '-wal';
        const shmPath = BACKUP.dbPath + '-shm';
        if (fs.existsSync(walPath)) fs.unlinkSync(walPath);
        if (fs.existsSync(shmPath)) fs.unlinkSync(shmPath);
        fs.renameSync(tmpRestore, BACKUP.dbPath);

        res.json({
          ok: true,
          restored: safeName,
          preRestoreBackup: `${preRestoreName}.gz`,
        });

        // Auto-restart the PM2 process so the app picks up the new DB.
        // Runs after the response is sent — the caller gets the JSON first.
        setTimeout(() => {
          try { execSync('pm2 restart ' + process.env.pm_id, { timeout: 10000 }); }
          catch { /* process is restarting, this will die */ }
        }, 500);
      } catch (err) {
        // Clean up temp file on failure
        const tmpRestore = path.join(backupDir, '_restore_tmp.db');
        if (fs.existsSync(tmpRestore)) fs.unlinkSync(tmpRestore);
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

  // ── GET /secret-scan — Check for secret leakage in public surface ────────
  // Reads process.env for sensitive values, then checks:
  //   1. HTTP responses on localhost (public endpoints)
  //   2. Static JS bundles on disk (frontend builds)
  // Returns { pass, scanned, leaks[] } — NEVER sends actual secret values.

  const SENSITIVE_KEY = /SECRET|_KEY|PASSWORD|TOKEN|PRIVATE|CREDENTIAL|ANTHROPIC|VAPID|CRYPTO_WALLET|SES_|SMTP/i;

  function collectSecrets() {
    const secrets = {};
    for (const [key, val] of Object.entries(process.env)) {
      if (!val || val.length < 8) continue;
      if (key.startsWith('npm_') || key.startsWith('NVM_') || key.startsWith('LC_')) continue;
      if (SENSITIVE_KEY.test(key)) {
        secrets[key] = val;
      }
    }
    return secrets;
  }

  function findJsFiles(dir, depth = 0) {
    if (depth >= 3) return [];
    const results = [];
    try {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory() && entry.name !== 'node_modules' && entry.name !== '.git') {
          results.push(...findJsFiles(full, depth + 1));
        } else if (entry.isFile() && (entry.name.endsWith('.js') || entry.name.endsWith('.html'))) {
          results.push(full);
        }
      }
    } catch {}
    return results;
  }

  router.get('/secret-scan', async (req, res) => {
    const port = process.env.PORT || 3000;
    const secrets = collectSecrets();
    const secretEntries = Object.entries(secrets);
    const leaks = [];

    // 1. HTTP probes — hit public endpoints on localhost
    const probePaths = ['/', '/.env', '/.git/config', '/health'];
    for (const p of probePaths) {
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 5000);
        const r = await fetch(`http://127.0.0.1:${port}${p}`, { signal: ctrl.signal });
        clearTimeout(timer);
        const body = await r.text();
        for (const [key, val] of secretEntries) {
          if (body.includes(val)) {
            leaks.push({ type: 'http', path: p, key, status: r.status });
          }
        }
      } catch {}
    }

    // 2. Disk scan — frontend bundles served as static files
    const projectRoot = opts.projectRoot ? path.resolve(opts.projectRoot) : process.cwd();
    const staticDirs = [
      path.join(projectRoot, 'public'),
      path.join(projectRoot, 'backend', 'public'),
      path.join(projectRoot, 'frontend', 'dist'),
      path.join(projectRoot, 'dist'),
    ];

    for (const dir of staticDirs) {
      if (!fs.existsSync(dir)) continue;
      const files = findJsFiles(dir);
      for (const file of files) {
        try {
          const content = fs.readFileSync(file, 'utf8');
          for (const [key, val] of secretEntries) {
            if (content.includes(val)) {
              leaks.push({ type: 'file', path: path.relative(projectRoot, file), key });
            }
          }
        } catch {}
      }
    }

    // 3. Check if .env file exists in any served directory
    for (const dir of staticDirs) {
      const envPath = path.join(dir, '.env');
      if (fs.existsSync(envPath)) {
        leaks.push({ type: 'file', path: path.relative(projectRoot, envPath), key: '.env_in_public_dir' });
      }
    }

    res.json({
      pass: leaks.length === 0,
      scanned: secretEntries.length,
      leaks,
    });
  });

  // ── GET /security-logs — Suspicious nginx log entries since last pull ────
  // Returns { events: [...], offset: <new_offset> }.
  // Caller should pass ?offset=<n> to resume from where it left off.
  // Parses the peerlinq nginx log format:
  //   IP DOMAIN [TIMESTAMP] "METHOD PATH PROTO" STATUS "UA"
  const NGINX_LOG = '/var/log/nginx/access-peerlinq.log';
  const LOG_RE = /^(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+"(.*)"$/;
  const PROBE_RE = /\.env|wp-admin|wp-login|phpmyadmin|\.git|\.DS_Store|\/admin|\/config|\/backup|\/debug|\/actuator|\/solr|\/cgi-bin|\/shell|\/eval|\/vendor|\/telescope|\/elfinder|\/api\/auth|\/authorize|\/auth\/login|\/auth\/register|\/auth\/reset|\/auth\/refresh|\/auth\/public-key|\/login/i;
  const MONTHS = { Jan:'01',Feb:'02',Mar:'03',Apr:'04',May:'05',Jun:'06',Jul:'07',Aug:'08',Sep:'09',Oct:'10',Nov:'11',Dec:'12' };

  router.get('/security-logs', (req, res) => {
    try {
      if (!fs.existsSync(NGINX_LOG)) return res.json({ events: [], offset: 0 });

      const filesize = fs.statSync(NGINX_LOG).size;
      let offset = parseInt(req.query.offset, 10) || 0;
      if (offset > filesize) offset = 0; // log rotated

      if (offset === filesize) return res.json({ events: [], offset: filesize });

      const events = [];
      const stream = fs.readFileSync(NGINX_LOG, 'utf8');
      const lines = stream.slice(offset).split('\n');

      for (const line of lines) {
        const m = line.match(LOG_RE);
        if (!m) continue;
        const [, ip, domain, tsRaw, method, reqPath, statusStr, ua] = m;
        const status = parseInt(statusStr, 10);
        if (status < 400 && !PROBE_RE.test(reqPath)) continue;

        // Convert '12/Apr/2026:10:30:00 +0000' → '2026-04-12 10:30:00'
        const p = tsRaw.split(/[/: ]/);
        const ts = p.length >= 6
          ? `${p[2]}-${MONTHS[p[1]] || '01'}-${p[0]} ${p[3]}:${p[4]}:${p[5]}`
          : tsRaw;

        events.push({
          ip, domain, method: method.slice(0, 10),
          path: reqPath.slice(0, 500), status,
          ua: ua.slice(0, 500), ts,
        });

        if (events.length >= 500) break;
      }

      res.json({ events, offset: filesize });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── GET /health — Structured health verdict for autonomous operations ──
  // Box-level checks always run. App-level checks are opt-in via opts.health.
  //
  // Usage:
  //   createSystemRoutes({
  //     systemKey: '...',
  //     health: {
  //       serviceName: 'aapta',
  //       sqlite: db,                              // better-sqlite3 instance
  //       s3: true,                                 // check IMDSv2 creds
  //       ssl: ['aapta.publicwerx.org'],            // check cert expiry
  //       authUrl: 'https://auth.publicwerx.org',   // check auth reachability
  //       custom: { name: async () => ({ status: 'pass' }) }
  //     }
  //   });
  //
  // Response: { status: 'healthy'|'degraded'|'unhealthy', service, checks: {...} }

  const HEALTH = opts.health || {};
  const SERVICE_NAME = HEALTH.serviceName || os.hostname();

  function checkDisk() {
    try {
      const df = execSync('df -h / | tail -1', { timeout: 3000 }).toString().trim().split(/\s+/);
      const pct = parseInt(df[4], 10);
      return {
        status: pct > 90 ? 'fail' : pct > 80 ? 'warn' : 'pass',
        use_pct: pct,
        available: df[3],
      };
    } catch (err) {
      return { status: 'fail', error: err.message };
    }
  }

  function checkMemory() {
    const total = os.totalmem();
    const free = os.freemem();
    const pct = Math.round((1 - free / total) * 100);
    return {
      status: pct > 90 ? 'fail' : pct > 80 ? 'warn' : 'pass',
      use_pct: pct,
      free_mb: Math.round(free / 1024 / 1024),
    };
  }

  function checkPm2() {
    try {
      const raw = execSync('pm2 jlist 2>/dev/null', { timeout: 5000 }).toString();
      const procs = JSON.parse(raw);
      const down = procs.filter(p => p.pm2_env?.status !== 'online');
      return {
        status: down.length > 0 ? 'warn' : 'pass',
        total: procs.length,
        online: procs.length - down.length,
        down: down.map(p => p.name),
      };
    } catch (err) {
      return { status: 'fail', error: err.message };
    }
  }

  function checkProcessHealth() {
    const mem = process.memoryUsage();
    return {
      status: 'pass',
      uptime_s: Math.floor(process.uptime()),
      rss_mb: Math.round(mem.rss / 1024 / 1024),
      heap_mb: Math.round(mem.heapUsed / 1024 / 1024),
    };
  }

  function checkNginx() {
    try {
      const status = execSync('systemctl is-active nginx 2>/dev/null', { timeout: 3000 })
        .toString().trim();
      return { status: status === 'active' ? 'pass' : 'fail', systemd: status };
    } catch {
      return { status: 'fail', systemd: 'unknown' };
    }
  }

  function checkOtel() {
    try {
      const status = execSync('systemctl is-active otelcol-contrib 2>/dev/null', { timeout: 3000 })
        .toString().trim();
      return { status: status === 'active' ? 'pass' : 'warn', systemd: status };
    } catch {
      return { status: 'warn', systemd: 'unknown' };
    }
  }

  function checkSqlite(db) {
    try {
      const readStart = Date.now();
      db.prepare('SELECT 1').get();
      const readMs = Date.now() - readStart;

      const intStart = Date.now();
      const result = db.pragma('quick_check(1)');
      const intMs = Date.now() - intStart;
      const ok = result?.[0]?.quick_check === 'ok';

      return {
        status: ok ? 'pass' : 'fail',
        read_ms: readMs,
        integrity_ms: intMs,
        integrity: ok,
      };
    } catch (err) {
      return { status: 'fail', error: err.message };
    }
  }

  async function checkS3Creds() {
    try {
      const start = Date.now();
      const creds = await getInstanceCredentials();
      const ms = Date.now() - start;
      if (!creds.AccessKeyId) return { status: 'fail', error: 'no credentials' };

      const expiration = new Date(creds.Expiration);
      const minutesLeft = Math.round((expiration - Date.now()) / 60000);

      return {
        status: minutesLeft < 5 ? 'warn' : 'pass',
        ms,
        creds_expire_min: minutesLeft,
      };
    } catch (err) {
      return { status: 'fail', error: err.message };
    }
  }

  async function checkSsl(domains) {
    const results = {};
    let worstStatus = 'pass';
    const DOMAIN_RE = /^[a-z0-9.-]+$/i;

    for (const domain of domains) {
      if (!DOMAIN_RE.test(domain)) {
        results[domain] = { status: 'fail', error: 'invalid domain' };
        worstStatus = 'fail';
        continue;
      }
      try {
        const raw = execSync(
          `echo | openssl s_client -servername "${domain}" -connect "${domain}:443" 2>/dev/null | openssl x509 -noout -enddate`,
          { timeout: 10000 },
        ).toString().trim();
        const dateStr = raw.replace('notAfter=', '');
        const expiry = new Date(dateStr);
        const daysLeft = Math.floor((expiry - Date.now()) / 86400000);

        let status = 'pass';
        if (daysLeft < 7) { status = 'fail'; worstStatus = 'fail'; }
        else if (daysLeft < 14) { status = 'warn'; if (worstStatus !== 'fail') worstStatus = 'warn'; }

        results[domain] = { status, days_remaining: daysLeft };
      } catch (err) {
        results[domain] = { status: 'fail', error: err.message };
        worstStatus = 'fail';
      }
    }

    return { status: worstStatus, domains: results };
  }

  async function checkAuthService(url) {
    try {
      const start = Date.now();
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 5000);
      const r = await fetch(`${url}/auth/public-key`, { signal: ctrl.signal });
      clearTimeout(t);
      return {
        status: r.ok ? 'pass' : 'warn',
        ms: Date.now() - start,
        http_status: r.status,
      };
    } catch (err) {
      return { status: 'warn', error: err.message };
    }
  }

  router.get('/health', async (req, res) => {
    const checks = {};

    // Box-level checks (always)
    checks.disk = checkDisk();
    checks.memory = checkMemory();
    checks.pm2 = checkPm2();
    checks.process = checkProcessHealth();
    checks.nginx = checkNginx();
    checks.otel = checkOtel();

    // App-level checks (opt-in)
    const promises = [];

    if (HEALTH.sqlite) {
      checks.sqlite = checkSqlite(HEALTH.sqlite);
    }
    if (HEALTH.s3) {
      promises.push(checkS3Creds().then(r => { checks.s3 = r; }));
    }
    if (HEALTH.ssl?.length) {
      promises.push(checkSsl(HEALTH.ssl).then(r => { checks.ssl = r; }));
    }
    if (HEALTH.authUrl) {
      promises.push(checkAuthService(HEALTH.authUrl).then(r => { checks.auth = r; }));
    }

    // Custom checks
    if (HEALTH.custom) {
      for (const [name, fn] of Object.entries(HEALTH.custom)) {
        promises.push(
          Promise.resolve().then(fn)
            .then(r => { checks[name] = r; })
            .catch(err => { checks[name] = { status: 'fail', error: err.message }; }),
        );
      }
    }

    if (promises.length) await Promise.all(promises);

    // Derive overall status from worst individual check
    let status = 'healthy';
    for (const check of Object.values(checks)) {
      if (check.status === 'fail') { status = 'unhealthy'; break; }
      if (check.status === 'warn') status = 'degraded';
    }

    res.json({
      status,
      service: SERVICE_NAME,
      timestamp: new Date().toISOString(),
      uptime: Math.floor(process.uptime()),
      checks,
    });
  });

  return router;
}

module.exports = { createSystemRoutes };
