-- health_log: storico fine degli eventi di salute (errori, degradi, rallentamenti)
-- campionati dai check di /api/status e dal cron. Scrittura da worker.js › logHealth,
-- lettura da GET /api/health-log (drill-down "esplora il giorno" della pagina /status).
-- NB: la colonna si chiama `check_name` (NON `check`: è parola riservata in SQLite).
CREATE TABLE IF NOT EXISTS health_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         INTEGER NOT NULL,            -- epoch ms (Date.now())
  status     TEXT    NOT NULL,            -- 'ok' | 'degraded' | 'error'
  latency    INTEGER,                     -- ms (NULL se non misurabile)
  check_name TEXT    NOT NULL,            -- 'archive' | 'signer' | 'anchor'
  cause      TEXT,                        -- es. 'slow' | 'timeout' | 'r2_error' | 'all_unreachable'
  detail     TEXT                         -- JSON opzionale (es. {"http":503})
);

-- Query per giorno: WHERE ts >= start AND ts < end → indice su ts.
CREATE INDEX IF NOT EXISTS idx_health_ts ON health_log(ts);
