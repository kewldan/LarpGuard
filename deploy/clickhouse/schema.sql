-- bot-shield analytics schema.
--
-- Events arrive over NATS (subjects botshield.events.conn / .req) into NATS
-- engine tables and are moved into MergeTree tables by materialized views.
-- The NATS engine subscribes to core NATS: events published while ClickHouse
-- is down are lost unless a JetStream stream buffers them for another
-- consumer. Raw events are kept 14 days, hourly fingerprint aggregates 180.
--
-- Change nats_url if NATS is not reachable as nats:4222.

CREATE DATABASE IF NOT EXISTS bot_shield;

-- Connections ---------------------------------------------------------------

CREATE TABLE IF NOT EXISTS bot_shield.conn_queue
(
    ts_ms        UInt64,
    instance     String,
    conn_id      UInt64,
    listener     String,
    ip_prefix    String,
    ip_hash      String,
    route        String,
    reason       String,
    duration_ms  UInt64,
    bytes_in     UInt64,
    bytes_out    UInt64,
    requests     UInt32,
    sni          String,
    tls_version  String,
    alpn_offered String,
    alpn         String,
    ja4          String,
    ja4_r        String,
    tcp_fp       String,
    ja4t         String,
    h2_fp        String
)
ENGINE = NATS
SETTINGS nats_url = 'nats:4222',
         nats_subjects = 'botshield.events.conn',
         nats_format = 'JSONEachRow',
         nats_skip_broken_messages = 100;

CREATE TABLE IF NOT EXISTS bot_shield.conn
(
    ts           DateTime64(3, 'UTC'),
    instance     LowCardinality(String),
    conn_id      UInt64,
    listener     LowCardinality(String),
    ip_prefix    String,
    ip_hash      String,
    route        LowCardinality(String),
    reason       LowCardinality(String),
    duration_ms  UInt64,
    bytes_in     UInt64,
    bytes_out    UInt64,
    requests     UInt32,
    sni          LowCardinality(String),
    tls_version  LowCardinality(String),
    alpn_offered LowCardinality(String),
    alpn         LowCardinality(String),
    ja4          String,
    ja4_r        String,
    tcp_fp       LowCardinality(String),
    ja4t         LowCardinality(String),
    h2_fp        LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (sni, ts)
TTL toDateTime(ts) + INTERVAL 14 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS bot_shield.conn_mv TO bot_shield.conn AS
SELECT fromUnixTimestamp64Milli(toInt64(ts_ms), 'UTC') AS ts, * EXCEPT ts_ms
FROM bot_shield.conn_queue;

-- Requests ------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS bot_shield.req_queue
(
    ts_ms              UInt64,
    instance           String,
    conn_id            UInt64,
    seq                UInt32,
    ip_prefix          String,
    ip_hash            String,
    http_version       String,
    method             String,
    host               String,
    path_group         String,
    header_fp          String,
    header_names       Array(String),
    pseudo_order       String,
    has_cookie         Bool,
    has_referer        Bool,
    sni                String,
    ja4                String,
    tcp_fp             String,
    ja4t               String,
    ja4h               String,
    h2_fp              String,
    user_agent         String,
    accept             String,
    accept_language    String,
    accept_encoding    String,
    sec_ch_ua          String,
    sec_ch_ua_mobile   String,
    sec_ch_ua_platform String,
    sec_fetch_site     String,
    sec_fetch_mode     String,
    sec_fetch_dest     String,
    sec_fetch_user     String,
    status             UInt16,
    duration_ms        UInt32,
    response_bytes     UInt64,
    local              Bool,
    score              Int16,
    class              String,
    reasons            Array(String),
    action             String,
    would_action       String
)
ENGINE = NATS
SETTINGS nats_url = 'nats:4222',
         nats_subjects = 'botshield.events.req',
         nats_format = 'JSONEachRow',
         nats_skip_broken_messages = 100;

CREATE TABLE IF NOT EXISTS bot_shield.req
(
    ts                 DateTime64(3, 'UTC'),
    instance           LowCardinality(String),
    conn_id            UInt64,
    seq                UInt32,
    ip_prefix          String,
    ip_hash            String,
    http_version       LowCardinality(String),
    method             LowCardinality(String),
    host               LowCardinality(String),
    path_group         String,
    header_fp          LowCardinality(String),
    header_names       Array(LowCardinality(String)),
    pseudo_order       LowCardinality(String),
    has_cookie         Bool,
    has_referer        Bool,
    sni                LowCardinality(String),
    ja4                String,
    tcp_fp             LowCardinality(String),
    ja4t               LowCardinality(String),
    ja4h               String,
    h2_fp              LowCardinality(String),
    user_agent         String,
    accept             LowCardinality(String),
    accept_language    LowCardinality(String),
    accept_encoding    LowCardinality(String),
    sec_ch_ua          LowCardinality(String),
    sec_ch_ua_mobile   LowCardinality(String),
    sec_ch_ua_platform LowCardinality(String),
    sec_fetch_site     LowCardinality(String),
    sec_fetch_mode     LowCardinality(String),
    sec_fetch_dest     LowCardinality(String),
    sec_fetch_user     LowCardinality(String),
    -- 0 when the client left before a response; absent for port 80 taps.
    status             UInt16,
    duration_ms        UInt32,
    response_bytes     UInt64,
    -- Answered by the gateway itself (502, block pages, ...).
    local              Bool,
    -- Verdict: score 0..100 (0 also when not scored), class, signals, what
    -- was done and what enforce mode would have done.
    score              Int16,
    class              LowCardinality(String),
    reasons            Array(LowCardinality(String)),
    action             LowCardinality(String),
    would_action       LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (host, ts)
TTL toDateTime(ts) + INTERVAL 14 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS bot_shield.req_mv TO bot_shield.req AS
SELECT fromUnixTimestamp64Milli(toInt64(ts_ms), 'UTC') AS ts, * EXCEPT ts_ms
FROM bot_shield.req_queue;

-- Hourly fingerprint clusters (input for the library and rules) ------------

CREATE TABLE IF NOT EXISTS bot_shield.fp_hourly
(
    hour         DateTime('UTC'),
    host         LowCardinality(String),
    ja4          String,
    h2_fp        LowCardinality(String),
    header_fp    LowCardinality(String),
    tcp_fp       LowCardinality(String),
    ua_sample    AggregateFunction(any, String),
    requests     SimpleAggregateFunction(sum, UInt64),
    clients      AggregateFunction(uniq, String),
    paths        AggregateFunction(uniq, String)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, host, ja4, h2_fp, header_fp, tcp_fp)
TTL hour + INTERVAL 180 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS bot_shield.fp_hourly_mv
TO bot_shield.fp_hourly AS
SELECT
    toStartOfHour(ts)     AS hour,
    host,
    ja4,
    h2_fp,
    header_fp,
    tcp_fp,
    anyState(user_agent)  AS ua_sample,
    toUInt64(count())     AS requests,
    uniqState(ip_hash)    AS clients,
    uniqState(path_group) AS paths
FROM bot_shield.req
GROUP BY hour, host, ja4, h2_fp, header_fp, tcp_fp;

-- Example: what shadow mode would block, by signal, last 24 hours.
--
-- SELECT arrayJoin(reasons) AS reason, count() AS requests,
--        uniqExact(ip_hash) AS clients
-- FROM bot_shield.req
-- WHERE ts >= now() - INTERVAL 1 DAY AND would_action = 'block'
-- GROUP BY reason ORDER BY requests DESC;

-- Example: fingerprint clusters of the last 24 hours, busiest first.
--
-- SELECT ja4, h2_fp, header_fp, anyMerge(ua_sample) AS ua,
--        sum(requests) AS requests, uniqMerge(clients) AS clients,
--        uniqMerge(paths) AS paths
-- FROM bot_shield.fp_hourly
-- WHERE hour >= now() - INTERVAL 1 DAY
-- GROUP BY ja4, h2_fp, header_fp
-- ORDER BY requests DESC
-- LIMIT 50;
