#!/usr/bin/env python3
"""Trains the model signal (docs/architecture.md, 6.1) from req events.

Reads feature vectors logged by the gateway (model.log_features) from
ClickHouse and weak labels from the verdict reasons, fits gradient-boosted
trees and writes them in the format src/model/gbdt.h loads.

Labels (requests that are neither are not used):
  automated: honeypot, honeypot_client, known_automation:*, fake_crawler:*,
             automation_user_agent, headless_user_agent
  human:     token_valid (solved the JS challenge); with --human-share also
             a sample of class=human requests with score 0

Usage: train_model.py --out model.json [--url http://127.0.0.1:8123]
                      [--days 14] [--trees 100] [--depth 4] [--rate 0.1]
                      [--human-share 0.2] [--limit 500000]
       train_model.py --fixture tests/data/gbdt_fixture.json   (test data)

Needs numpy. Review the printed validation numbers before deploying: the
model only advises (signal weight "model"), but a bad one adds noise.
"""

import argparse
import json
import math
import sys
import urllib.parse
import urllib.request

import numpy as np

# src/model/features.h; the gateway refuses a model for another set.
FEATURE_SET = "f1"
FEATURE_NAMES = [
    "http2", "offered_h2", "header_count", "has_cookie", "has_referer",
    "has_accept_language", "has_accept_encoding", "has_sec_ch_ua",
    "has_sec_fetch", "ua_length", "method_get", "has_query",
    "engine_chromium", "engine_firefox", "engine_webkit", "engine_none",
    "ua_mobile",
    "tls13", "tls_ciphers", "tls_extensions", "alpn_h2", "tls_sni",
    "ttl_64", "ttl_128", "ttl_unknown",
    "navigation", "api", "asset",
    "sig_ua_tls_mismatch", "sig_ua_h2_mismatch", "sig_browser_without_h2",
    "sig_missing_client_hints", "sig_missing_fetch_metadata",
    "sig_missing_accept_language", "sig_os_tcp_mismatch",
    "sig_behavior_regular_timing", "sig_behavior_not_found",
    "sig_behavior_api_without_page", "sig_behavior_no_assets",
    "sig_behavior_sequential_ids"]

AUTOMATED = ("honeypot", "honeypot_client", "automation_user_agent",
             "headless_user_agent")
AUTOMATED_PREFIXES = ("known_automation:", "fake_crawler:")

QUERY = """
SELECT features, reasons, class, score
FROM bot_shield.req
WHERE ts >= now() - INTERVAL {days:UInt32} DAY
  AND length(features) = {width:UInt32}
  AND (hasAny(reasons, ['honeypot', 'honeypot_client',
                        'automation_user_agent', 'headless_user_agent',
                        'token_valid'])
       OR arrayExists(r -> startsWith(r, 'known_automation:')
                           OR startsWith(r, 'fake_crawler:'), reasons)
       OR (class = 'human' AND score = 0
           AND rand() / 4294967295.0 < {human_share:Float64}))
LIMIT {limit:UInt32}
FORMAT JSONEachRow
"""


def label(reasons, bot_class, score):
    """1 automated, 0 human, None unusable."""
    if any(r in AUTOMATED or r.startswith(AUTOMATED_PREFIXES)
           for r in reasons):
        return 1
    if "token_valid" in reasons or (bot_class == "human" and score == 0):
        return 0
    return None


def fetch(url, days, human_share, limit):
    params = {"query": QUERY, "param_days": days,
              "param_width": len(FEATURE_NAMES),
              "param_human_share": human_share, "param_limit": limit}
    request = urllib.request.Request(
        url.rstrip("/") + "/?" + urllib.parse.urlencode(params))
    xs, ys = [], []
    with urllib.request.urlopen(request, timeout=600) as response:
        for line in response:
            row = json.loads(line)
            y = label(row["reasons"], row["class"], row["score"])
            if y is not None:
                xs.append(row["features"])
                ys.append(y)
    return (np.asarray(xs, dtype=np.float32).reshape(-1, len(FEATURE_NAMES)),
            np.asarray(ys, dtype=np.float64))


def thresholds(column, max_bins=32):
    """Split candidates: left side is x < threshold (as in gbdt.cc)."""
    values = np.unique(column)
    if len(values) <= max_bins + 1:
        return values[1:].astype(np.float32)
    quantiles = np.quantile(column, np.linspace(0, 1, max_bins + 2)[1:-1])
    return np.unique(quantiles.astype(np.float32))


class Trees:
    """Gradient-boosted regression trees on the log-loss."""

    def __init__(self, trees, depth, rate, l2=1.0, min_hessian=1.0):
        self.n_trees, self.depth, self.rate = trees, depth, rate
        self.l2, self.min_hessian = l2, min_hessian
        self.base = 0.0
        self.trees = []

    def fit(self, x, y, weight):
        self.edges = [thresholds(x[:, f]) for f in range(x.shape[1])]
        # Bin index: number of thresholds <= x; x < edges[j] <=> bin <= j.
        self.bins = np.stack(
            [np.searchsorted(e, x[:, f], side="right")
             for f, e in enumerate(self.edges)], axis=1)
        p = np.clip(np.average(y, weights=weight), 1e-6, 1 - 1e-6)
        self.base = math.log(p / (1 - p))
        raw = np.full(len(y), self.base)
        for _ in range(self.n_trees):
            prob = 1 / (1 + np.exp(-raw))
            grad = (prob - y) * weight
            hess = np.maximum(prob * (1 - prob), 1e-6) * weight
            tree = {"feature": [], "threshold": [], "left": [], "right": [],
                    "value": []}
            self._grow(tree, np.arange(len(y)), grad, hess, 0)
            self.trees.append(tree)
            raw += self._predict_tree(tree, x)

    def _new_node(self, tree):
        for key in tree:
            tree[key].append(-1 if key in ("feature", "left", "right")
                             else 0.0)
        return len(tree["value"]) - 1

    def _grow(self, tree, rows, grad, hess, level):
        node = self._new_node(tree)
        g, h = grad[rows].sum(), hess[rows].sum()
        best = None
        if level < self.depth and h >= 2 * self.min_hessian:
            parent = g * g / (h + self.l2)
            for f, edges in enumerate(self.edges):
                if len(edges) == 0:
                    continue
                b = self.bins[rows, f]
                gh = np.bincount(b, weights=grad[rows], minlength=len(edges) + 1)
                hh = np.bincount(b, weights=hess[rows], minlength=len(edges) + 1)
                gl, hl = np.cumsum(gh)[:-1], np.cumsum(hh)[:-1]
                gr, hr = g - gl, h - hl
                ok = (hl >= self.min_hessian) & (hr >= self.min_hessian)
                if not ok.any():
                    continue
                gain = np.where(ok, gl * gl / (hl + self.l2) +
                                gr * gr / (hr + self.l2) - parent, -np.inf)
                j = int(np.argmax(gain))
                if gain[j] > 1e-9 and (best is None or gain[j] > best[0]):
                    best = (gain[j], f, j)
        if best is None:
            tree["value"][node] = float(-g / (h + self.l2) * self.rate)
            return node
        _, f, j = best
        left_rows = rows[self.bins[rows, f] <= j]
        right_rows = rows[self.bins[rows, f] > j]
        tree["feature"][node] = f
        tree["threshold"][node] = float(self.edges[f][j])
        tree["left"][node] = self._grow(tree, left_rows, grad, hess, level + 1)
        tree["right"][node] = self._grow(tree, right_rows, grad, hess,
                                         level + 1)
        return node

    @staticmethod
    def _predict_tree(tree, x):
        out = np.empty(len(x))
        for r in range(len(x)):
            i = 0
            while tree["left"][i] >= 0:
                i = (tree["left"][i]
                     if x[r, tree["feature"][i]] < tree["threshold"][i]
                     else tree["right"][i])
            out[r] = tree["value"][i]
        return out

    def predict(self, x):
        raw = np.full(len(x), self.base)
        for tree in self.trees:
            raw += self._predict_tree(tree, x)
        return 1 / (1 + np.exp(-raw))

    def to_json(self):
        return {"format": "bot-shield-gbdt", "feature_set": FEATURE_SET,
                "features": FEATURE_NAMES, "base": self.base,
                "trees": self.trees}


def report(model, x, y):
    p = model.predict(x)
    for threshold in (0.5, 0.8, 0.9):
        flagged = p >= threshold
        tp = int((flagged & (y == 1)).sum())
        fp = int((flagged & (y == 0)).sum())
        print(f"  threshold {threshold}: recall {tp / max(1, (y == 1).sum()):.3f}"
              f", false positives {fp / max(1, (y == 0).sum()):.4f}")


def synthetic(rows, seed):
    """Labelled vectors with a learnable pattern (fixture, smoke tests)."""
    rng = np.random.default_rng(seed)
    x = np.zeros((rows, len(FEATURE_NAMES)), dtype=np.float32)
    y = rng.integers(0, 2, rows).astype(np.float64)
    bot = y == 1
    x[:, 2] = np.where(bot, rng.integers(2, 8, rows), rng.integers(8, 20, rows))
    x[:, 3] = (~bot) & (rng.random(rows) < 0.9)
    x[:, 7] = (~bot) & (rng.random(rows) < 0.8)
    x[:, 9] = rng.uniform(0.1, 1.5, rows)
    x[:, 18] = rng.integers(10, 20, rows)
    x[:, 35] = bot & (rng.random(rows) < 0.5)
    noise = rng.random(rows) < 0.05  # Some labels are wrong.
    y[noise] = 1 - y[noise]
    return x, y


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default="http://127.0.0.1:8123")
    parser.add_argument("--out")
    parser.add_argument("--fixture", help="write a test fixture and exit")
    parser.add_argument("--days", type=int, default=14)
    parser.add_argument("--trees", type=int, default=100)
    parser.add_argument("--depth", type=int, default=4)
    parser.add_argument("--rate", type=float, default=0.1)
    parser.add_argument("--human-share", type=float, default=0.2)
    parser.add_argument("--limit", type=int, default=500000)
    args = parser.parse_args()

    if args.fixture:
        x, y = synthetic(2000, seed=7)
        model = Trees(trees=10, depth=3, rate=0.3)
        model.fit(x, y, np.ones(len(y)))
        samples, _ = synthetic(20, seed=8)
        with open(args.fixture, "w") as f:
            json.dump({"model": model.to_json(),
                       "samples": samples.tolist(),
                       "expected": model.predict(samples).tolist()}, f)
        return
    if not args.out:
        sys.exit("--out is required")

    try:
        x, y = fetch(args.url, args.days, args.human_share, args.limit)
    except OSError as e:
        sys.exit(f"cannot query ClickHouse at {args.url}: {e}")
    automated, human = int((y == 1).sum()), int((y == 0).sum())
    print(f"{len(y)} labelled requests: {automated} automated, {human} human")
    if automated < 100 or human < 100:
        sys.exit("not enough labelled data (need 100 of each)")
    # Balance the classes; hold out 20 % for validation.
    weight = np.where(y == 1, len(y) / (2 * automated), len(y) / (2 * human))
    order = np.random.default_rng(1).permutation(len(y))
    cut = int(len(y) * 0.8)
    train, test = order[:cut], order[cut:]
    model = Trees(args.trees, args.depth, args.rate)
    model.fit(x[train], y[train], weight[train])
    print("validation:")
    report(model, x[test], y[test])
    with open(args.out, "w") as f:
        json.dump(model.to_json(), f)
    print(f"wrote {args.out} ({len(model.trees)} trees)")


if __name__ == "__main__":
    main()
