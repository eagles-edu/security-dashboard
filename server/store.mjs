import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

const DAY = 86_400_000;

export function createStore(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o750 });
  const db = new Database(path.join(directory, 'security-dashboard.sqlite'));
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  db.pragma('busy_timeout = 5000');
  db.exec(`
    CREATE TABLE IF NOT EXISTS metric_hourly (
      bucket INTEGER NOT NULL,
      site TEXT NOT NULL,
      requests INTEGER NOT NULL DEFAULT 0,
      suspicious INTEGER NOT NULL DEFAULT 0,
      crowdsec_http INTEGER NOT NULL DEFAULT 0,
      crowdsec_ssh INTEGER NOT NULL DEFAULT 0,
      crowdsec_other INTEGER NOT NULL DEFAULT 0,
      fail2ban_ssh INTEGER NOT NULL DEFAULT 0,
      firewall_blocks INTEGER NOT NULL DEFAULT 0,
      active_bans INTEGER,
      PRIMARY KEY (bucket, site)
    );
    CREATE TABLE IF NOT EXISTS ip_hourly (
      bucket INTEGER NOT NULL,
      ip TEXT NOT NULL,
      source TEXT NOT NULL,
      signals INTEGER NOT NULL DEFAULT 0,
      last_seen INTEGER NOT NULL,
      PRIMARY KEY (bucket, ip, source)
    );
    CREATE TABLE IF NOT EXISTS ip_retention (
      ip TEXT PRIMARY KEY,
      retain_until INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS file_cursor (
      path TEXT PRIMARY KEY,
      inode TEXT NOT NULL,
      offset INTEGER NOT NULL,
      size INTEGER NOT NULL,
      mtime INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS archive_done (
      path TEXT NOT NULL,
      size INTEGER NOT NULL,
      mtime INTEGER NOT NULL,
      PRIMARY KEY(path, size, mtime)
    );
    CREATE TABLE IF NOT EXISTS seen_alerts (
      id TEXT PRIMARY KEY,
      bucket INTEGER NOT NULL,
      ip TEXT,
      source TEXT NOT NULL,
      scenario TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS metadata (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_metric_bucket ON metric_hourly(bucket);
    CREATE INDEX IF NOT EXISTS idx_ip_bucket ON ip_hourly(ip, bucket);
    CREATE INDEX IF NOT EXISTS idx_alert_bucket ON seen_alerts(bucket);
  `);

  const metric = db.prepare(`
    INSERT INTO metric_hourly(bucket, site, requests, suspicious)
    VALUES (@bucket, @site, @requests, @suspicious)
    ON CONFLICT(bucket, site) DO UPDATE SET
      requests = requests + excluded.requests,
      suspicious = suspicious + excluded.suspicious
  `);
  const ipSignal = db.prepare(`
    INSERT INTO ip_hourly(bucket, ip, source, signals, last_seen)
    VALUES (@bucket, @ip, @source, @signals, @lastSeen)
    ON CONFLICT(bucket, ip, source) DO UPDATE SET
      signals = signals + excluded.signals,
      last_seen = MAX(last_seen, excluded.last_seen)
  `);
  const sourceMetrics = Object.fromEntries([
    'crowdsec_http', 'crowdsec_ssh', 'crowdsec_other', 'fail2ban_ssh',
  ].map((column) => [column, db.prepare(`
    INSERT INTO metric_hourly(bucket, site, ${column}) VALUES (@bucket, 'host', 1)
    ON CONFLICT(bucket, site) DO UPDATE SET ${column} = ${column} + 1
  `)]));

  function bucketFor(timestamp) {
    return Math.floor(timestamp / 3_600_000) * 3_600_000;
  }

  function addRequest({ timestamp, site, ip, suspicious }) {
    const bucket = bucketFor(timestamp);
    metric.run({ bucket, site, requests: 1, suspicious: suspicious ? 1 : 0 });
    if (suspicious && ip) ipSignal.run({ bucket, ip, source: 'nginx_signal', signals: 1, lastSeen: timestamp });
  }

  function addSourceEvent({ id, timestamp, ip, source, scenario = '' }) {
    if (id && db.prepare('SELECT 1 FROM seen_alerts WHERE id = ?').get(String(id))) return false;
    const bucket = bucketFor(timestamp);
    const statement = sourceMetrics[source];
    if (statement) statement.run({ bucket });
    if (id) db.prepare('INSERT OR IGNORE INTO seen_alerts(id,bucket,ip,source,scenario) VALUES (?,?,?,?,?)')
      .run(String(id), bucket, ip || null, source, scenario);
    if (ip) ipSignal.run({ bucket, ip, source, signals: 1, lastSeen: timestamp });
    return true;
  }

  function recordFirewallDelta(timestamp, packets) {
    const bucket = bucketFor(timestamp);
    db.prepare(`INSERT INTO metric_hourly(bucket,site,firewall_blocks)
      VALUES (?, 'host', ?) ON CONFLICT(bucket,site) DO UPDATE SET
      firewall_blocks = firewall_blocks + excluded.firewall_blocks`).run(bucket, packets);
  }

  function recordActiveBans(timestamp, count) {
    const bucket = bucketFor(timestamp);
    db.prepare(`INSERT INTO metric_hourly(bucket,site,active_bans)
      VALUES (?, 'host', ?) ON CONFLICT(bucket,site) DO UPDATE SET
      active_bans = excluded.active_bans`).run(bucket, count);
  }

  function getTotals(since, site = 'all') {
    const requestFilter = site === 'all' ? "site != 'host'" : 'site = @site';
    const cutoffBucket = bucketFor(since);
    return db.prepare(`SELECT
      COALESCE((SELECT SUM(requests) FROM metric_hourly WHERE bucket >= @since AND ${requestFilter}),0) requests,
      COALESCE((SELECT SUM(suspicious) FROM metric_hourly WHERE bucket >= @since AND ${requestFilter}),0) suspicious,
      COALESCE((SELECT SUM(crowdsec_http + crowdsec_ssh + crowdsec_other) FROM metric_hourly WHERE bucket >= @since AND site = 'host'),0) crowdsec,
      COALESCE((SELECT SUM(crowdsec_http) FROM metric_hourly WHERE bucket >= @since AND site = 'host'),0) crowdsecHttp,
      COALESCE((SELECT SUM(crowdsec_ssh) FROM metric_hourly WHERE bucket >= @since AND site = 'host'),0) crowdsecSsh,
      COALESCE((SELECT SUM(fail2ban_ssh) FROM metric_hourly WHERE bucket >= @since AND site = 'host'),0) fail2ban,
      COALESCE((SELECT SUM(firewall_blocks) FROM metric_hourly WHERE bucket >= @since AND site = 'host'),0) firewall`).get(site === 'all' ? { since: cutoffBucket } : { since: cutoffBucket, site });
  }

  function getTrends(since, site = 'all') {
    const requestFilter = site === 'all' ? "site != 'host'" : 'site = @site';
    const cutoffBucket = bucketFor(since);
    return db.prepare(`WITH host AS (
        SELECT bucket, SUM(crowdsec_http + crowdsec_ssh + crowdsec_other) crowdsec,
          SUM(fail2ban_ssh) fail2ban, SUM(firewall_blocks) firewall, MAX(active_bans) active_bans
        FROM metric_hourly WHERE bucket >= @since AND site = 'host' GROUP BY bucket
      ), requests AS (
        SELECT bucket, SUM(requests) requests, SUM(suspicious) suspicious
        FROM metric_hourly WHERE bucket >= @since AND ${requestFilter} GROUP BY bucket
      )
      SELECT COALESCE(requests.bucket, host.bucket) bucket, requests.requests, requests.suspicious,
        host.crowdsec, host.fail2ban, host.firewall, host.active_bans
      FROM requests FULL OUTER JOIN host ON requests.bucket = host.bucket
      ORDER BY bucket`).all(site === 'all' ? { since: cutoffBucket } : { since: cutoffBucket, site });
  }

  function getIpSignals(ip, since) {
    return db.prepare('SELECT COALESCE(SUM(signals),0) AS count, MAX(last_seen) AS last_seen FROM ip_hourly WHERE ip = ? AND bucket >= ?')
      .get(ip, bucketFor(since));
  }

  function retainIpHistory(ip, retainUntil) {
    db.prepare(`INSERT INTO ip_retention(ip, retain_until) VALUES (?, ?)
      ON CONFLICT(ip) DO UPDATE SET retain_until = MAX(retain_until, excluded.retain_until)`)
      .run(ip, Math.trunc(retainUntil));
  }

  function getSites() {
    return db.prepare("SELECT DISTINCT site FROM metric_hourly WHERE site != 'host' ORDER BY site").all().map((row) => row.site);
  }

  function getCoverage() {
    return db.prepare('SELECT MIN(bucket) start, MAX(bucket) end FROM metric_hourly').get();
  }

  function getMeta(key) {
    return db.prepare('SELECT value FROM metadata WHERE key = ?').get(key)?.value ?? null;
  }

  function setMeta(key, value) {
    db.prepare('INSERT INTO metadata(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value')
      .run(key, String(value));
  }

  function getCursor(filePath) {
    return db.prepare('SELECT inode, offset, size, mtime FROM file_cursor WHERE path = ?').get(filePath) ?? null;
  }

  function setCursor(filePath, inode, offset, size, mtime) {
    db.prepare(`INSERT INTO file_cursor(path,inode,offset,size,mtime) VALUES(?,?,?,?,?)
      ON CONFLICT(path) DO UPDATE SET inode=excluded.inode, offset=excluded.offset,
      size=excluded.size, mtime=excluded.mtime`).run(filePath, inode, offset, size, mtime);
  }

  function archiveProcessed(filePath, size, mtime) {
    return Boolean(db.prepare('SELECT 1 FROM archive_done WHERE path=? AND size=? AND mtime=?').get(filePath, size, mtime));
  }

  function markArchiveProcessed(filePath, size, mtime) {
    db.prepare('INSERT OR IGNORE INTO archive_done(path,size,mtime) VALUES(?,?,?)').run(filePath, size, mtime);
  }

  function prune(now = Date.now()) {
    const cutoff = now - 90 * DAY;
    const cutoffBucket = bucketFor(cutoff);
    const pruneTx = db.transaction(() => {
      db.prepare('DELETE FROM metric_hourly WHERE bucket < ?').run(cutoffBucket);
      db.prepare(`DELETE FROM ip_hourly WHERE bucket < ? AND ip NOT IN
        (SELECT ip FROM ip_retention WHERE retain_until > ?)`)
        .run(cutoffBucket, now);
      db.prepare('DELETE FROM ip_retention WHERE retain_until <= ?').run(now);
      db.prepare('DELETE FROM seen_alerts WHERE bucket < ?').run(cutoffBucket);
      db.prepare('DELETE FROM archive_done WHERE mtime < ?').run(cutoff);
    });
    pruneTx();
  }

  return {
    db, addRequest, addSourceEvent, recordFirewallDelta, recordActiveBans,
    getTotals, getTrends, getIpSignals, retainIpHistory, getSites, getCoverage, getMeta, setMeta,
    getCursor, setCursor, archiveProcessed, markArchiveProcessed, prune,
    close: () => db.close(),
  };
}
