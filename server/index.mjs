import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createStore } from './store.mjs';
import { ingestNginxLogs, ingestFail2banLog } from './nginx.mjs';

const execFileAsync = promisify(execFile);
const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const HOST = '127.0.0.1';
const PORT = Number(process.env.PORT || 4311);
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');
const LOG_DIR = process.env.NGINX_LOG_DIR || '/var/log/nginx';
const HELPER_SOCKET = process.env.SECURITY_HELPER_SOCKET || '/run/security-dashboard/dashboard.sock';
const GEOIP = process.env.GEOIP_COUNTRY_DB || '/usr/share/GeoIP/GeoLite2-Country.mmdb';
const RETENTION_MS = 90 * 86_400_000;
const store = createStore(DATA_DIR);
const countryCache = new Map();
let live = { bans: [], sources: {}, protected_networks: [], fail2ban: null, updated_at: null };
let logState = { nginx: { status: 'pending', files: 0, added: 0 }, fail2banLog: { status: 'pending', files: 0, added: 0 } };
let lastCollectionError = null;
let collectionRunning = false;

function sendJson(response, status, body) {
  const output = JSON.stringify(body);
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(output),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
  });
  response.end(output);
}

function normalizeRange(value) {
  if (value === '24h') return { name: '24h', since: Date.now() - 86_400_000, bucket: 'hour' };
  if (value === '7d') return { name: '7d', since: Date.now() - 7 * 86_400_000, bucket: 'day' };
  return { name: '90d', since: Date.now() - RETENTION_MS, bucket: 'day' };
}

function normalizeSite(value) {
  if (!value || value === 'all') return 'all';
  const known = store.getSites();
  return known.includes(value) ? value : 'all';
}

async function readBody(request, limit = 8_192) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > limit) throw new Error('Request body is too large');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
}

async function helper(operation, payload) {
  return new Promise((resolve, reject) => {
    const connection = net.createConnection({ path: HELPER_SOCKET });
    let output = '';
    let settled = false;
    connection.setTimeout(90_000);
    connection.on('connect', () => {
      connection.end(`${JSON.stringify({ operation, payload })}\n`);
    });
    connection.on('data', (chunk) => {
      output += chunk.toString('utf8');
      if (output.length > 64 * 1024 * 1024) {
        settled = true;
        connection.destroy();
        reject(new Error('Security helper response exceeded the size limit'));
      }
    });
    connection.on('timeout', () => {
      settled = true;
      connection.destroy();
      reject(new Error('Security helper timed out'));
    });
    connection.on('error', (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    });
    connection.on('end', () => {
      if (settled) return;
      settled = true;
      try {
        const result = JSON.parse(output);
        if (result.error) reject(Object.assign(new Error(result.error), { stderr: result.error }));
        else resolve(result);
      } catch (error) {
        reject(error);
      }
    });
  });
}

function metricClass(scenario = '') {
  const value = scenario.toLowerCase();
  if (/(?:http|web|nginx|wordpress|drupal|joomla)/.test(value)) return 'crowdsec_http';
  if (/(?:ssh|sshd)/.test(value)) return 'crowdsec_ssh';
  return 'crowdsec_other';
}

function eventTimestamp(alert) {
  const value = alert.created_at || alert.timestamp || alert.events?.[0]?.timestamp;
  const timestamp = Date.parse(value || '');
  return Number.isFinite(timestamp) ? timestamp : Date.now();
}

function eventIp(alert) {
  for (const event of alert.events || []) {
    for (const meta of event.meta || []) {
      if (meta.key === 'source_ip' && net.isIP(String(meta.value || '').split('%', 1)[0])) {
        return String(meta.value).split('%', 1)[0];
      }
    }
  }
  return null;
}

function sourceEvents(payload) {
  const alerts = Array.isArray(payload.alerts) ? payload.alerts : [];
  let added = 0;
  for (const alert of alerts) {
    const scenario = String(alert.scenario || alert.events?.[0]?.scenario || '');
    added += Number(store.addSourceEvent({
      id: `crowdsec:${alert.id ?? `${eventTimestamp(alert)}:${eventIp(alert) ?? 'unknown'}:${scenario}`}`,
      timestamp: eventTimestamp(alert),
      ip: eventIp(alert),
      source: metricClass(scenario),
      scenario,
    }));
  }
  return added;
}

function fail2banBlockEvents(payload) {
  const active = new Set((payload.fail2ban?.bans || []).map((ban) => ban.ip));
  return active;
}

async function collect() {
  if (collectionRunning) return;
  collectionRunning = true;
  const now = Date.now();
  try {
    const [nginx, fail2banLog] = await Promise.all([
      ingestNginxLogs(store, LOG_DIR, now),
      ingestFail2banLog(store, '/var/log', now),
    ]);
    logState = { nginx, fail2banLog };
    const payload = await helper('collect');
    sourceEvents(payload);
    const active = Array.isArray(payload.bans) ? payload.bans.filter((ban) => ban.active !== false) : [];
    const activeBans = new Set(active.map((ban) => ban.ip));
    store.recordActiveBans(now, activeBans.size);

    if (Number.isFinite(payload.firewall_packets)) {
      const previous = Number(store.getMeta('firewall_packets'));
      const delta = Number.isFinite(previous) && payload.firewall_packets >= previous
        ? payload.firewall_packets - previous : payload.firewall_packets;
      if (delta > 0) store.recordFirewallDelta(now, delta);
      store.setMeta('firewall_packets', payload.firewall_packets);
    }
    store.setMeta('coverage_start', store.getMeta('coverage_start') || now);
    live = { ...payload, bans: active, updated_at: now };
    lastCollectionError = null;
  } catch (error) {
    lastCollectionError = error.stderr?.trim() || error.message;
    live.updated_at ??= null;
  } finally {
    store.prune(now);
    collectionRunning = false;
  }
}

async function countryFor(ip) {
  if (countryCache.has(ip)) return countryCache.get(ip);
  let country = null;
  try {
    const [codeResult, nameResult] = await Promise.all([
      execFileAsync('mmdblookup', ['--file', GEOIP, '--ip', ip, 'country', 'iso_code'], { timeout: 1_500, maxBuffer: 2_048 }),
      execFileAsync('mmdblookup', ['--file', GEOIP, '--ip', ip, 'country', 'names', 'en'], { timeout: 1_500, maxBuffer: 2_048 }),
    ]);
    const code = /"([A-Z]{2})" <utf8_string>/.exec(codeResult.stdout)?.[1];
    const name = /"([^"]+)" <utf8_string>/.exec(nameResult.stdout)?.[1];
    if (code && name) country = { code, name };
  } catch {
    country = null;
  }
  countryCache.set(ip, country);
  return country;
}

async function banRows() {
  const now = Date.now();
  const rows = live.bans || [];
  return Promise.all(rows.map(async (ban) => {
    const day = store.getIpSignals(ban.ip, now - 86_400_000);
    const ninety = store.getIpSignals(ban.ip, now - RETENTION_MS);
    return {
      ip: ban.ip,
      country: await countryFor(ban.ip),
      source: (ban.sources || []).join(', ') || (ban.manual ? 'Manual dashboard ban' : 'Unknown source'),
      reason: (ban.reasons || []).join('; ') || 'No source reason provided',
      signals24h: day.count,
      signals90d: ninety.count,
      lastSeen: Math.max(day.last_seen || 0, ninety.last_seen || 0, Date.parse(ban.last_seen || '') || 0),
      manual: Boolean(ban.manual),
      persistent: Boolean(ban.persistent),
      protected: Boolean(ban.protected),
    };
  }));
}

function sourceHealth() {
  const sources = live.sources || {};
  return {
    generatedAt: live.updated_at,
    stale: !live.updated_at || Date.now() - live.updated_at > 120_000,
    collectorError: lastCollectionError,
    sources: {
      nginx: { status: logState.nginx.status, files: logState.nginx.files, error: null },
      crowdsec: sources.crowdsec || { status: 'unavailable', error: lastCollectionError || 'Collector has not completed' },
      crowdsecAlerts: sources.crowdsecAlerts || { status: 'unavailable', error: lastCollectionError || 'Collector has not completed' },
      fail2ban: sources.fail2ban || { status: 'unavailable', error: lastCollectionError || 'Collector has not completed' },
      fail2banLog: {
        status: logState.fail2banLog.status,
        files: logState.fail2banLog.files,
        error: logState.fail2banLog.status === 'partial' ? 'Some Fail2ban logs could not be read' : null,
      },
      firewall: sources.firewall || { status: 'unavailable', error: lastCollectionError || 'Collector has not completed' },
      geoip: {
        status: GEOIP && fsSync.existsSync(GEOIP) ? 'ok' : 'unavailable',
        path: GEOIP,
        error: GEOIP && fsSync.existsSync(GEOIP) ? null : 'Local GeoIP database is unavailable',
      },
      oneShield: sources.oneShield || { status: 'not_connected', error: 'Edge event feed is not configured; origin telemetry only' },
    },
    protectedNetworks: live.protected_networks || [],
  };
}

function requireSameOrigin(request) {
  const expectedOrigin = `http://${HOST}:${PORT}`;
  if (request.headers.origin !== expectedOrigin) throw Object.assign(new Error('Same-origin request required'), { status: 403 });
  const fetchSite = request.headers['sec-fetch-site'];
  if (fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'none') {
    throw Object.assign(new Error('Cross-origin request rejected'), { status: 403 });
  }
}

async function api(request, response, url) {
  if (request.method === 'GET' && url.pathname === '/api/health') {
    return sendJson(response, 200, { ok: true, host: HOST, port: PORT, updatedAt: live.updated_at });
  }
  if (request.method === 'GET' && url.pathname === '/api/summary') {
    const range = normalizeRange(url.searchParams.get('range'));
    const site = normalizeSite(url.searchParams.get('site'));
    const totals = store.getTotals(range.since, site);
    const uniqueBans = new Set((live.bans || []).map((ban) => ban.ip));
    return sendJson(response, 200, {
      range: range.name,
      site,
      totals: { ...totals, activeBans: uniqueBans.size },
      coverage: store.getCoverage(),
      coverageStartedAt: Number(store.getMeta('coverage_start')) || null,
      updatedAt: live.updated_at,
      stale: !live.updated_at || Date.now() - live.updated_at > 120_000,
    });
  }
  if (request.method === 'GET' && url.pathname === '/api/trends') {
    const range = normalizeRange(url.searchParams.get('range'));
    return sendJson(response, 200, {
      range: range.name,
      granularity: range.name === '24h' ? 'hour' : 'day',
      site: normalizeSite(url.searchParams.get('site')),
      points: store.getTrends(range.since, normalizeSite(url.searchParams.get('site'))),
      sites: store.getSites(),
      coverage: store.getCoverage(),
      coverageStartedAt: Number(store.getMeta('coverage_start')) || null,
    });
  }
  if (request.method === 'GET' && url.pathname === '/api/bans') {
    return sendJson(response, 200, { bans: await banRows(), updatedAt: live.updated_at });
  }
  if (request.method === 'GET' && url.pathname === '/api/sources') {
    return sendJson(response, 200, sourceHealth());
  }
  if (request.method === 'POST' && url.pathname === '/api/collect') {
    requireSameOrigin(request);
    await collect();
    return sendJson(response, lastCollectionError ? 503 : 200, { ...sourceHealth() });
  }
  if (request.method === 'POST' && url.pathname === '/api/bans') {
    requireSameOrigin(request);
    const body = await readBody(request);
    const result = await helper('ban', { ip: String(body.ip || '').trim(), reason: String(body.reason || '').trim() });
    await collect();
    return sendJson(response, 201, result);
  }
  const unbanMatch = /^\/api\/bans\/([^/]+)$/.exec(url.pathname);
  if (request.method === 'DELETE' && unbanMatch) {
    requireSameOrigin(request);
    const ip = decodeURIComponent(unbanMatch[1]);
    const result = await helper('unban', { ip, reason: 'Manual unban from security dashboard' });
    if (!result.ok) {
      await collect();
      return sendJson(response, 502, {
        ...result,
        error: 'Source cleanup failed; persistent enforcement was retained. Check CrowdSec and Fail2ban health, then retry the manual unban.',
      });
    }
    store.retainIpHistory(ip, Date.now() + RETENTION_MS);
    await collect();
    return sendJson(response, 200, result);
  }
  return sendJson(response, 404, { error: 'Not found' });
}

async function serveStatic(request, response, url) {
  const dist = path.join(ROOT, 'dist');
  const requested = url.pathname === '/' ? '/index.html' : url.pathname;
  const resolved = path.resolve(dist, `.${requested}`);
  if (!resolved.startsWith(`${dist}${path.sep}`)) return sendJson(response, 400, { error: 'Invalid path' });
  let filePath = resolved;
  try {
    const stat = await fs.stat(filePath);
    if (!stat.isFile()) filePath = path.join(dist, 'index.html');
  } catch {
    filePath = path.join(dist, 'index.html');
  }
  try {
    const body = await fs.readFile(filePath);
    const ext = path.extname(filePath);
    const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml' };
    response.writeHead(200, {
      'content-type': types[ext] || 'application/octet-stream',
      'content-length': body.length,
      'cache-control': ext === '.html' ? 'no-store' : 'public, max-age=31536000, immutable',
      'x-content-type-options': 'nosniff',
      'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
      'referrer-policy': 'no-referrer',
      'x-frame-options': 'DENY',
    });
    response.end(body);
  } catch {
    sendJson(response, 503, { error: 'Dashboard build is missing; run npm run build' });
  }
}

const server = http.createServer(async (request, response) => {
  try {
    const host = request.headers.host;
    if (host !== `${HOST}:${PORT}` && host !== `localhost:${PORT}`) {
      return sendJson(response, 403, { error: 'This service accepts local host requests only' });
    }
    const url = new URL(request.url || '/', `http://${HOST}:${PORT}`);
    if (url.pathname.startsWith('/api/')) return await api(request, response, url);
    if (request.method !== 'GET' && request.method !== 'HEAD') return sendJson(response, 405, { error: 'Method not allowed' });
    return await serveStatic(request, response, url);
  } catch (error) {
    const status = Number(error.status) || (error.message === 'Request body is too large' ? 413 : /protected|address|Reason|invalid|A single/.test(error.message) ? 400 : 500);
    return sendJson(response, status, { error: error.stderr?.trim() || error.message });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Security dashboard listening on http://${HOST}:${PORT}`);
  void collect();
  setInterval(() => void collect(), 30_000).unref();
});

function shutdown() {
  server.close(() => {
    store.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 5_000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
