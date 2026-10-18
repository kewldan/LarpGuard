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
    would_action       String,
    rate_limit         String,
    request_id         String,
    watermark          String,
    features           Array(Float32),
    model_score        Nullable(Float32)
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
    would_action       LowCardinality(String),
    -- Rate limit that refused the request (action/would_action rate_limit).
    rate_limit         LowCardinality(String),
    -- Also sent to Traefik as X-Bot-Request-Id; see GET /decisions/<id>.
    request_id         String,
    -- Token in a decoy answer (action decoy): search leaked data for it.
    watermark          String,
    -- Model feature vector (src/model/features.h; training data for
    -- tools/train_model.py) and the model's probability (NULL: no model).
    features           Array(Float32),
    model_score        Nullable(Float32)
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (host, ts)
TTL toDateTime(ts) + INTERVAL 14 DAY;

-- Upgrades of existing installations (no-ops on new ones). The NATS queue
-- table cannot be altered: for new queue columns drop bot_shield.req_mv and
-- bot_shield.req_queue and run this file again.
ALTER TABLE bot_shield.req ADD COLUMN IF NOT EXISTS watermark String;
ALTER TABLE bot_shield.req ADD COLUMN IF NOT EXISTS features Array(Float32);
ALTER TABLE bot_shield.req ADD COLUMN IF NOT EXISTS model_score Nullable(Float32);

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

-- Daily clusters with behaviour anomalies (input for cluster candidates) ---

CREATE TABLE IF NOT EXISTS bot_shield.cluster_daily
(
    day         Date,
    ja4         String,
    h2_fp       LowCardinality(String),
    header_fp   LowCardinality(String),
    ua_sample   AggregateFunction(any, String),
    first_seen  SimpleAggregateFunction(min, DateTime64(3, 'UTC')),
    requests    SimpleAggregateFunction(sum, UInt64),
    -- Requests with behaviour, honeypot or fake-crawler signals.
    anomalous   SimpleAggregateFunction(sum, UInt64),
    honeypot    SimpleAggregateFunction(sum, UInt64),
    bots        SimpleAggregateFunction(sum, UInt64),
    -- Requests the library already knows (known_automation:*).
    known       SimpleAggregateFunction(sum, UInt64),
    clients     AggregateFunction(uniq, String),
    hosts       AggregateFunction(uniq, String),
    reason_top  AggregateFunction(topKArray(5), Array(String))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (day, ja4, h2_fp, header_fp)
TTL day + INTERVAL 180 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS bot_shield.cluster_daily_mv
TO bot_shield.cluster_daily AS
SELECT
    toDate(ts)                AS day,
    ja4,
    h2_fp,
    header_fp,
    anyState(user_agent)      AS ua_sample,
    min(ts)                   AS first_seen,
    toUInt64(count())         AS requests,
    toUInt64(countIf(arrayExists(
        r -> startsWith(r, 'behavior_') OR startsWith(r, 'honeypot')
             OR startsWith(r, 'fake_crawler'), reasons))) AS anomalous,
    toUInt64(countIf(has(reasons, 'honeypot')))          AS honeypot,
    toUInt64(countIf(class = 'bot'))                     AS bots,
    toUInt64(countIf(arrayExists(
        r -> startsWith(r, 'known_automation:'), reasons))) AS known,
    uniqState(ip_hash)        AS clients,
    uniqState(host)           AS hosts,
    topKArrayState(5)(reasons) AS reason_top
FROM bot_shield.req
WHERE class != 'verified_bot' AND score >= 0
GROUP BY day, ja4, h2_fp, header_fp;

-- Clusters worth adding to the library: many anomalies or honeypot hits,
-- not matched by a known signature yet. tools/cluster_candidates.py reads
-- it; by hand:
--   SELECT * FROM bot_shield.cluster_candidates(days = 7,
--       min_requests = 100, min_anomaly = 0.3);
CREATE VIEW IF NOT EXISTS bot_shield.cluster_candidates AS
SELECT ja4, h2_fp, header_fp, ua_sample, total AS requests, clients, hosts,
       anomaly_ratio, honeypot_hits AS honeypot, bot_ratio, top_reasons,
       first AS first_seen
FROM
(
    SELECT ja4, h2_fp, header_fp,
           anyMerge(ua_sample)                 AS ua_sample,
           sum(requests)                       AS total,
           uniqMerge(clients)                  AS clients,
           uniqMerge(hosts)                    AS hosts,
           sum(anomalous) / sum(requests)      AS anomaly_ratio,
           sum(honeypot)                       AS honeypot_hits,
           sum(bots) / sum(requests)           AS bot_ratio,
           sum(known)                          AS known_hits,
           topKArrayMerge(5)(reason_top)       AS top_reasons,
           min(first_seen)                     AS first
    FROM bot_shield.cluster_daily
    WHERE day >= today() - {days:UInt32}
    GROUP BY ja4, h2_fp, header_fp
)
WHERE total >= {min_requests:UInt64} AND known_hits = 0
  AND (anomaly_ratio >= {min_anomaly:Float64} OR honeypot_hits > 0)
ORDER BY honeypot_hits > 0 DESC, anomaly_ratio * log10(total) DESC;

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
