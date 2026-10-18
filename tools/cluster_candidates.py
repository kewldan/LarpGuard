#!/usr/bin/env python3
"""Fingerprint clusters worth a look (docs/architecture.md, 10.4).

Reads bot_shield.cluster_candidates from ClickHouse over HTTP and prints the
clusters with many behaviour anomalies or honeypot hits that the library
does not know yet, busiest first. With --yaml it prints entries for the
`automation:` list of deploy/fingerprints.yaml instead; review them before
adding (a cluster can be one big NAT of real browsers).

Usage: cluster_candidates.py [--url http://127.0.0.1:8123] [--days 7]
                             [--min-requests 100] [--min-anomaly 0.3]
                             [--limit 30] [--yaml]
"""

import argparse
import json
import sys
import urllib.parse
import urllib.request

QUERY = """
SELECT ja4, h2_fp, header_fp, ua_sample, requests, clients, hosts,
       anomaly_ratio, honeypot, bot_ratio, top_reasons,
       toString(first_seen) AS first_seen
FROM bot_shield.cluster_candidates(days = {days:UInt32},
                                   min_requests = {min_requests:UInt64},
                                   min_anomaly = {min_anomaly:Float64})
LIMIT {limit:UInt32}
FORMAT JSONEachRow
"""


def fetch(url, params):
    query = {"query": QUERY, **{f"param_{k}": str(v) for k, v in params.items()}}
    request = urllib.request.Request(
        url.rstrip("/") + "/?" + urllib.parse.urlencode(query))
    with urllib.request.urlopen(request, timeout=60) as response:
        body = response.read().decode()
    return [json.loads(line) for line in body.splitlines() if line.strip()]


def yaml_string(text):
    return json.dumps(text)  # JSON strings are valid YAML scalars.


def print_yaml(rows):
    print("# Candidates from tools/cluster_candidates.py; review first.")
    for index, row in enumerate(rows, 1):
        # A few honeypot hits in an otherwise quiet cluster may be one
        # client behind a shared NAT: suggest less.
        if row["anomaly_ratio"] >= 0.6:
            weight = 80
        elif row["anomaly_ratio"] >= 0.3:
            weight = 50
        else:
            weight = 30
        print(f"  - id: cluster-{row['ja4'][:10] or 'nottls'}-{index}")
        print(f"    # {row['requests']} requests, {row['clients']} clients, "
              f"anomalies {row['anomaly_ratio']:.0%}, ua: "
              f"{row['ua_sample'][:60]}")
        print(f"    weight: {weight}")
        print(f"    ja4: {yaml_string(row['ja4'])}")
        print(f"    h2_fingerprint: {yaml_string(row['h2_fp'])}")
        print(f"    header_fp: {yaml_string(row['header_fp'])}")
        print('    user_agent: ""')


def print_table(rows):
    if not rows:
        print("no candidates")
        return
    for row in rows:
        print(f"{row['requests']:>9} req {row['clients']:>6} clients "
              f"{row['hosts']:>3} hosts  anomalies {row['anomaly_ratio']:>4.0%} "
              f"bot {row['bot_ratio']:>4.0%} honeypot {row['honeypot']:>4}  "
              f"since {row['first_seen']}")
        print(f"    ja4={row['ja4']} header_fp={row['header_fp']}")
        print(f"    h2_fp={row['h2_fp'] or '-'}")
        print(f"    ua={row['ua_sample'][:100]}")
        print(f"    reasons={', '.join(row['top_reasons'])}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default="http://127.0.0.1:8123")
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--min-requests", type=int, default=100)
    parser.add_argument("--min-anomaly", type=float, default=0.3)
    parser.add_argument("--limit", type=int, default=30)
    parser.add_argument("--yaml", action="store_true")
    args = parser.parse_args()
    try:
        rows = fetch(args.url, {"days": args.days,
                                "min_requests": args.min_requests,
                                "min_anomaly": args.min_anomaly,
                                "limit": args.limit})
    except OSError as e:
        sys.exit(f"cannot query ClickHouse at {args.url}: {e}")
    (print_yaml if args.yaml else print_table)(rows)


if __name__ == "__main__":
    main()
