import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { ingestFail2banLog, parseAccessLine, siteFromLogPath } from '../server/nginx.mjs';
import { createStore } from '../server/store.mjs';

test('Nginx parser counts requests separately from suspicious request signals', () => {
  const ordinary = parseAccessLine('203.0.113.9 - - [29/Oct/2026:10:00:00 +0000] "GET /courses HTTP/1.1" 200 1420 "-" "test"');
  const probe = parseAccessLine('203.0.113.10 - - [29/Oct/2026:10:01:00 +0000] "GET /.env HTTP/1.1" 404 120 "-" "test"');

  assert.equal(ordinary?.status, 200);
  assert.equal(ordinary?.suspicious, false);
  assert.equal(probe?.status, 404);
  assert.equal(probe?.suspicious, true);
  assert.equal(parseAccessLine('not an access log line'), null);
});

test('Nginx log names map to stable site labels', () => {
  assert.equal(siteFromLogPath('/var/log/nginx/access.log'), 'default');
  assert.equal(siteFromLogPath('/var/log/nginx/eagles_edu_vn_access.log'), 'eagles.edu.vn');
  assert.equal(siteFromLogPath('/var/log/nginx/admin_eagles_edu_vn_access_ssl.log.1.gz'), 'admin.eagles.edu.vn');
});

test('Fail2ban event logs are ingested as distinct source detections', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'security-dashboard-fail2ban-test-'));
  const store = createStore(path.join(directory, 'db'));
  try {
    fs.writeFileSync(path.join(directory, 'fail2ban.log'), '[2026-10-29 10:00:00] [sshd] Ban 203.0.113.77\n');
    const result = await ingestFail2banLog(store, directory, Date.parse('2026-10-29T10:01:00Z'));
    assert.equal(result.status, 'ok');
    assert.equal(result.files, 1);
    assert.equal(result.added, 1);
    assert.equal(store.getTotals(Date.parse('2026-10-29T09:00:00Z')).fail2ban, 1);
  } finally {
    store.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('SQLite aggregates source-separated counts, deduplicates alerts, and retains IP history', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'security-dashboard-test-'));
  const store = createStore(directory);
  const now = Date.now();
  try {
    store.addRequest({ timestamp: now, site: 'eagles.edu.vn', ip: '203.0.113.10', suspicious: false });
    store.addRequest({ timestamp: now, site: 'eagles.edu.vn', ip: '203.0.113.10', suspicious: true });
    const alert = { id: 'alert-1', timestamp: now, ip: '203.0.113.10', source: 'crowdsec_http', scenario: 'http-probing' };

    assert.equal(store.addSourceEvent(alert), true);
    assert.equal(store.addSourceEvent(alert), false);
    store.addSourceEvent({ id: 'fail2ban-1', timestamp: now, ip: '203.0.113.10', source: 'fail2ban_ssh', scenario: 'sshd' });
    store.recordFirewallDelta(now, 7);
    store.recordActiveBans(now, 2);

    const totals = store.getTotals(now - 60_000, 'all');
    assert.equal(totals.requests, 2);
    assert.equal(totals.suspicious, 1);
    assert.equal(totals.crowdsec, 1);
    assert.equal(totals.fail2ban, 1);
    assert.equal(totals.firewall, 7);
    assert.equal(store.getIpSignals('203.0.113.10', now - 60_000).count, 3);
    assert.equal(store.getTrends(now - 60_000, 'all').length, 1);
    assert.equal(store.getTrends(now - 60_000, 'all')[0].fail2ban, 1);
    assert.equal(store.getTrends(now - 60_000, 'all')[0].firewall, 7);
    assert.deepEqual(store.getSites(), ['eagles.edu.vn']);

    store.prune(now + 91 * 86_400_000);
    assert.equal(store.getIpSignals('203.0.113.10', now - 60_000).count, 0);
  } finally {
    store.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('manual unban retention preserves per-IP history for 90 days after unban', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'security-dashboard-retention-test-'));
  const store = createStore(directory);
  const now = Date.now();
  const ip = '203.0.113.42';
  try {
    store.addRequest({ timestamp: now - 80 * 86_400_000, site: 'eagles.edu.vn', ip, suspicious: true });
    store.retainIpHistory(ip, now + 90 * 86_400_000);
    store.prune(now + 20 * 86_400_000);
    assert.equal(store.getIpSignals(ip, now - 90 * 86_400_000).count, 1);

    store.prune(now + 91 * 86_400_000);
    assert.equal(store.getIpSignals(ip, now - 90 * 86_400_000).count, 0);
  } finally {
    store.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('server binds only to loopback and rejects cross-origin control requests', () => {
  const source = fs.readFileSync(new URL('../server/index.mjs', import.meta.url), 'utf8');
  assert.match(source, /const HOST = '127\.0\.0\.1'/);
  assert.match(source, /request\.headers\.origin !== expectedOrigin/);
  assert.match(source, /request\.headers\.host/);
  assert.match(source, /SECURITY_HELPER_SOCKET/);
  assert.doesNotMatch(source, /execFileAsync\('sudo'/);
  assert.doesNotMatch(source, /setTimeout\([^\n]*unban/i);
  assert.match(source, /store\.retainIpHistory\(ip, Date\.now\(\) \+ RETENTION_MS\)/);
});

test('trend chart renders source-separated Fail2ban and confirmed-firewall series', () => {
  const source = fs.readFileSync(new URL('../src/App.jsx', import.meta.url), 'utf8');
  assert.match(source, /className="series-line fail2ban"/);
  assert.match(source, /className="series-line firewall"/);
  assert.match(source, />Fail2ban bans</);
  assert.match(source, />Confirmed blocks</);
});

test('root helper enforces durable bans without automatic expiry', () => {
  const helper = fs.readFileSync(new URL('../scripts/security-dashboard-helper.py', import.meta.url), 'utf8');
  assert.match(helper, /"bans": \{\}/);
  assert.match(helper, /def restore\(\)/);
  assert.match(helper, /def manual_unban\(payload\)/);
  assert.match(helper, /def is_protected\(ip, networks\)/);
  assert.match(helper, /DASHBOARD_SKIP_FIREWALL/);
  assert.doesNotMatch(helper, /expiration|expires|auto.?unban/i);
});
