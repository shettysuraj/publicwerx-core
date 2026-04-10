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
