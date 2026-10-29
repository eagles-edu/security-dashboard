import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { createGunzip } from 'node:zlib';
import readline from 'node:readline';

const ACCESS_LINE = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+([^\s"]+)(?:\s+HTTP\/[^\"]*)?"\s+(\d{3})\s+(\d+|-)\s+/;
const SUSPICIOUS_PATH = /(?:^|\/)(?:wp-login\.php|wp-admin(?:\/|$)|xmlrpc\.php|phpmyadmin(?:\/|$)|pma(?:\/|$)|\.env(?:\/|$)|\.git(?:\/|$)|vendor\/phpunit|actuator(?:\/|$)|cgi-bin(?:\/|$)|boaform)(?:[/?#]|$)|(?:\.\.|%2e%2e)(?:\/|%2f)|union(?:\+|%20|\s)+select|<script|\/etc\/passwd|(?:;|\||%3b|%7c)(?:whoami|curl|wget|bash|sh)(?:\b|%20)/i;
const MONTHS = new Map(['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'].map((name, index) => [name, index]));
const HISTORY_MS = 90 * 86_400_000;

export function parseAccessLine(line) {
  const match = ACCESS_LINE.exec(line);
  if (!match) return null;
  const [, ip, rawTime, method, uri, status, bytes] = match;
  const timeMatch = /^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})$/.exec(rawTime);
  if (!timeMatch) return null;
  const [, day, month, year, hour, minute, second, zone] = timeMatch;
  const monthIndex = MONTHS.get(month);
  if (monthIndex === undefined) return null;
  const sign = zone[0] === '-' ? -1 : 1;
  const offset = sign * (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(3, 5)));
  const timestamp = Date.UTC(Number(year), monthIndex, Number(day), Number(hour), Number(minute), Number(second)) - offset * 60_000;
  const safeUri = uri.split(/[?#]/, 1)[0];
  return {
    ip: ip.replace(/^::ffff:/i, ''),
    timestamp,
    method,
    status: Number(status),
    bytes: bytes === '-' ? 0 : Number(bytes),
    suspicious: SUSPICIOUS_PATH.test(safeUri) || method === 'TRACE' || method === 'CONNECT',
  };
}

export function siteFromLogPath(filePath) {
  const base = path.basename(filePath);
  if (base === 'access.log' || /^access\.log\./.test(base)) return 'default';
  let slug = base.replace(/\.gz$/, '').replace(/\.log(?:\.\d+)?$/, '');
  slug = slug.replace(/_access(?:_\d+|_ssl)?$/, '').replace(/_access.*$/, '');
  slug = slug.replace(/_/g, '.').replace(/\.+/g, '.').replace(/^\.|\.$/g, '');
  return slug || 'default';
}

async function* linesFor(filePath, compressed, start = 0, end = undefined) {
  let stream = fs.createReadStream(filePath, start || end !== undefined ? { start, ...(end === undefined ? {} : { end }) } : undefined);
  if (compressed) stream = stream.pipe(createGunzip());
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
  try {
    for await (const line of rl) yield line;
  } finally {
    rl.close();
    stream.destroy();
  }
}

export async function ingestNginxLogs(store, logDir = '/var/log/nginx', now = Date.now()) {
  let entries;
  try {
    entries = await fsp.readdir(logDir, { withFileTypes: true });
  } catch {
    return { files: 0, added: 0, status: 'unavailable' };
  }
  const files = entries.filter((entry) => entry.isFile() && /access.*\.log(?:\.\d+)?(?:\.gz)?$|^access\.log(?:\.\d+)?(?:\.gz)?$/.test(entry.name))
    .map((entry) => path.join(logDir, entry.name)).sort();
  let added = 0;
  let filesRead = 0;
  let unavailable = false;

  for (const filePath of files) {
    let stat;
    try { stat = await fsp.stat(filePath); } catch (error) {
      if (error.code !== 'ENOENT') unavailable = true;
      continue;
    }
    if (now - stat.mtimeMs > HISTORY_MS) continue;
    filesRead += 1;
    const compressed = filePath.endsWith('.gz');
    const rotated = /\.log\.\d+(?:\.gz)?$/.test(filePath);
    const site = siteFromLogPath(filePath);

    if (rotated) {
      if (store.archiveProcessed(filePath, stat.size, Math.floor(stat.mtimeMs))) continue;
      try {
        for await (const line of linesFor(filePath, compressed)) {
          const parsed = parseAccessLine(line);
          if (parsed && parsed.timestamp >= now - HISTORY_MS) {
            store.addRequest({ ...parsed, site });
            added += 1;
          }
        }
        store.markArchiveProcessed(filePath, stat.size, Math.floor(stat.mtimeMs));
      } catch {
        unavailable = true;
      }
      continue;
    }

    const inode = `${stat.dev}:${stat.ino}`;
    const cursor = store.getCursor(filePath);
    const offset = cursor && cursor.inode === inode && stat.size >= cursor.offset ? cursor.offset : 0;
    if (stat.size === offset) continue;
    try {
      for await (const line of linesFor(filePath, false, offset, Math.max(offset, stat.size - 1))) {
        const parsed = parseAccessLine(line);
        if (parsed && parsed.timestamp >= now - HISTORY_MS) {
          store.addRequest({ ...parsed, site });
          added += 1;
        }
      }
      const after = await fsp.stat(filePath);
      store.setCursor(filePath, inode, stat.size, after.size, Math.floor(after.mtimeMs));
    } catch {
      unavailable = true;
    }
  }
  return { files: filesRead, added, status: unavailable ? 'partial' : filesRead ? 'ok' : 'unavailable' };
}

export async function ingestFail2banLog(store, logDir = '/var/log', now = Date.now()) {
  const candidates = ['fail2ban.log', ...Array.from({ length: 14 }, (_, index) => `fail2ban.log.${index + 1}`)];
  let added = 0;
  let files = 0;
  let available = false;
  let unreadable = false;
  for (const name of candidates) {
    const filePath = path.join(logDir, name);
    let stat;
    try { stat = await fsp.stat(filePath); } catch (error) {
      if (error.code !== 'ENOENT') unreadable = true;
      continue;
    }
    available = true;
    files += 1;
    const rotated = name !== 'fail2ban.log';
    if (rotated && store.archiveProcessed(filePath, stat.size, Math.floor(stat.mtimeMs))) continue;
    const inode = `${stat.dev}:${stat.ino}`;
    const cursor = store.getCursor(filePath);
    const offset = rotated ? 0 : cursor && cursor.inode === inode && stat.size >= cursor.offset ? cursor.offset : 0;
    if (!rotated && stat.size === offset) continue;
    try {
      const end = rotated ? undefined : Math.max(offset, stat.size - 1);
      for await (const line of linesFor(filePath, false, offset, end)) {
        const match = /\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\].*\[sshd\].*\bBan\s+(\S+)/.exec(line);
        if (!match) continue;
        const timestamp = Date.parse(`${match[1]}Z`);
        if (!Number.isFinite(timestamp) || timestamp < now - HISTORY_MS) continue;
        store.addSourceEvent({
          id: `fail2ban:${filePath}:${match[1]}:${match[2]}`,
          timestamp,
          ip: match[2],
          source: 'fail2ban_ssh',
          scenario: 'sshd',
        });
        added += 1;
      }
      if (rotated) store.markArchiveProcessed(filePath, stat.size, Math.floor(stat.mtimeMs));
      else {
        const after = await fsp.stat(filePath);
        store.setCursor(filePath, inode, stat.size, after.size, Math.floor(after.mtimeMs));
      }
    } catch {
      unreadable = true;
    }
  }
  return { files, added, status: unreadable ? 'partial' : available ? 'ok' : 'unavailable' };
}
