import { describe, expect, it } from 'vitest';
import { MOCK_CONFIG } from '../../server/dev/mock-config.ts';
import { niceCeil, sparkPoints } from './chart-math.ts';
import { limitYaml, perSecond, ruleYaml } from './config-yaml.ts';
import { diffLines, diffSegments } from './diff.ts';
import { filterToText, parseFilterText } from './filter-text.ts';
import {
  ago,
  compact,
  countdown,
  duration,
  lineColumn,
  percent,
  shorten,
} from './format.ts';
import { highlight } from './rule-syntax.ts';
import { reasonWeight, thresholdsOf, weightColor } from './signals.ts';
import { parseClaim } from './user-agent.ts';

describe('format', () => {
  it('compacts numbers like the design', () => {
    expect(compact(12480)).toBe('12.5k');
    expect(compact(9402)).toBe('9,402');
    expect(compact(4.25)).toBe('4.3');
    expect(compact(0.041)).toBe('0.04');
    expect(compact(0)).toBe('0');
    expect(compact(2_500_000)).toBe('2.5M');
    expect(percent(1, 4)).toBe('25.0%');
    expect(percent(1, 0)).toBe('0%');
  });

  it('formats times', () => {
    expect(countdown(2537)).toBe('42:17');
    expect(countdown(4000)).toBe('1:06:40');
    expect(duration(3_600_000)).toBe('1h');
    expect(duration(90_000)).toBe('90s');
    expect(ago(1000, 1000)).toBe('now');
    expect(ago(0, 4 * 60_000)).toBe('4 min ago');
    expect(ago(0, 3 * 86_400_000)).toBe('3 d ago');
  });

  it('shortens fingerprints and finds line and column', () => {
    expect(shorten('t13d1516h2_8daaf6152771_02713d6af862')).toBe(
      't13d1516h2_8daa…f862',
    );
    expect(shorten('short')).toBe('short');
    expect(lineColumn('ab\ncd', 5)).toEqual({ line: 2, col: 2 });
    expect(lineColumn('ab', 1)).toEqual({ line: 1, col: 1 });
  });
});

describe('filter text', () => {
  it('round-trips filters', () => {
    const text =
      'host:shop.example.com action:block,challenge class:bot asn:64496 ip:203.0.113.0/24 score>=40';
    const parsed = parseFilterText(text);
    expect(parsed).toEqual({
      ok: true,
      filter: {
        host: 'shop.example.com',
        action: ['block', 'challenge'],
        class: ['bot'],
        asn: 64496,
        ip_prefix: '203.0.113.0/24',
        min_score: 40,
      },
    });
    if (parsed.ok)
      expect(parseFilterText(filterToText(parsed.filter))).toEqual(parsed);
  });

  it('refuses typos instead of widening the result', () => {
    expect(parseFilterText('hots:a').ok).toBe(false);
    expect(parseFilterText('action:explode').ok).toBe(false);
    expect(parseFilterText('asn:ASx').ok).toBe(false);
    expect(parseFilterText('score>200').ok).toBe(false);
    expect(parseFilterText('score>40')).toEqual({
      ok: true,
      filter: { min_score: 41 },
    });
    expect(parseFilterText('  ')).toEqual({ ok: true, filter: {} });
  });
});

describe('diff', () => {
  it('marks differing fingerprint segments', () => {
    expect(diffSegments('a_b_c', 'a_x_c', '_')).toEqual([
      { text: 'a_', changed: false },
      { text: 'b_', changed: true },
      { text: 'c', changed: false },
    ]);
  });

  it('diffs lines', () => {
    expect(diffLines(['a', 'b', 'c'], ['a', 'c', 'd'])).toEqual([
      { mark: ' ', text: 'a' },
      { mark: '-', text: 'b' },
      { mark: ' ', text: 'c' },
      { mark: '+', text: 'd' },
    ]);
    expect(diffLines([], ['x'])).toEqual([{ mark: '+', text: 'x' }]);
  });
});

describe('signals', () => {
  it('weighs reasons from the configuration', () => {
    expect(reasonWeight('ua_tls_mismatch', MOCK_CONFIG)).toBe(32);
    expect(reasonWeight('rule:mobile_app', MOCK_CONFIG)).toBe(-40);
    expect(reasonWeight('rule:hard_block', MOCK_CONFIG)).toBeNull();
    expect(reasonWeight('known_automation:go_http', MOCK_CONFIG)).toBe(50);
    expect(reasonWeight('token_valid', MOCK_CONFIG)).toBe(-40);
    expect(reasonWeight('list:4', MOCK_CONFIG)).toBeNull();
    expect(reasonWeight('x', undefined)).toBeNull();
    expect(thresholdsOf(MOCK_CONFIG)).toEqual({ challenge: 30, block: 70 });
    expect(weightColor(-5)).toBe('var(--color-verified)');
    expect(weightColor(25)).toBe('var(--color-blocked-text)');
    expect(weightColor(10)).toBe('var(--color-challenged-text)');
  });
});

describe('config snippets', () => {
  it('writes rule and limit YAML', () => {
    expect(
      ruleYaml({
        name: 'r',
        when: 'score > 40\n  and path ~ "/x\'"',
        action: 'block',
        score: 0,
      }),
    ).toBe(
      `rules:\n  - name: r\n    when: 'score > 40 and path ~ "/x''"'\n    action: block`,
    );
    expect(
      ruleYaml({ name: 's', when: 'true', action: 'score', score: -10 }),
    ).toContain('score: -10');
    const limit = MOCK_CONFIG.rate_limits[1];
    if (!limit) throw new Error('fixture');
    expect(perSecond(limit)).toBe(10);
    expect(limitYaml(limit, 10, 20)).toBe(
      'rate_limits:\n  - name: search_api\n    hosts: [shop.example.com]\n    paths: ["/search"]\n    classes: [suspicious, bot]\n    key: [ip_prefix, ja4]\n    rate: 10/s\n    burst: 20',
    );
    expect(
      limitYaml({ ...limit, key: ['header:x-api-key'] }, 0.5, 1),
    ).toContain('key: ["header:x-api-key"]');
    expect(limitYaml(limit, 0.5, 1)).toContain('rate: 30/m');
  });
});

describe('rule syntax', () => {
  it('colors fields, keywords, strings and unknown names', () => {
    const tokens = highlight('score >= 40 and hots == "a"').filter((t) =>
      t.text.trim(),
    );
    expect(tokens.map((t) => t.text)).toEqual([
      'score',
      '>=',
      '40',
      'and',
      'hots',
      '==',
      '"a"',
    ]);
    expect(tokens[0]?.weight).toBe(500);
    expect(tokens[2]?.color).toBe('var(--color-verified)');
    expect(tokens[3]?.color).toBe('var(--color-text-3)');
    expect(tokens[4]?.color).toBe('var(--color-blocked-text)');
    expect(tokens[6]?.color).toBe('var(--color-healthy)');
  });
});

describe('chart math', () => {
  it('rounds axis maxima and draws polylines', () => {
    expect(niceCeil(9.6)).toBe(10);
    expect(niceCeil(11)).toBe(20);
    expect(niceCeil(230)).toBe(250);
    expect(niceCeil(0)).toBe(1);
    expect(sparkPoints([0, 5, 10], 10, 12)).toBe('0.0,11.0 5.0,6.0 10.0,1.0');
    expect(sparkPoints([], 10, 10)).toBe('');
  });
});

describe('user agent claims', () => {
  it('names the claimed browser and OS', () => {
    expect(
      parseClaim(
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      ),
    ).toEqual({ browser: 'Chrome 131', os: 'macOS' });
    expect(parseClaim('curl/8.7.1')).toEqual({ browser: 'curl 8.7.1', os: '' });
    expect(
      parseClaim(
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
      ).browser,
    ).toBe('Googlebot');
    expect(
      parseClaim('Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/131.0.0.0')
        .browser,
    ).toBe('Headless Chrome 131');
    expect(parseClaim('').browser).toBe('empty');
  });
});
