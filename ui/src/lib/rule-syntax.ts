// Syntax highlighting of the gateway's rule language.

// The rule language's names (src/score/rules.cc).
const FIELDS = new Set([
  'host',
  'method',
  'path',
  'http_version',
  'sni',
  'alpn',
  'ja4',
  'h2_fp',
  'pseudo_order',
  'header_fp',
  'tcp_fp',
  'user_agent',
  'ua_family',
  'ua_engine',
  'ua_os',
  'ua_tool',
  'score',
  'class',
  'reasons',
  'asn',
  'asn_org',
  'asn_country',
  'asn_hosting',
  'signed_agent',
]);
const KEYWORDS = new Set(['and', 'or', 'not', 'in']);
const FUNCTIONS = new Set(['header', 'has_header', 'cidr']);

interface Token {
  text: string;
  color: string;
  weight: number;
}

export function highlight(line: string): Token[] {
  const tokens: Token[] = [];
  const pattern =
    /(\s+|"(?:[^"\\]|\\.)*"?|-?\d+|[A-Za-z_]\w*|==|!=|<=|>=|[<>~()[\],]|.)/g;
  for (const match of line.matchAll(pattern)) {
    const text = match[0];
    let color = 'var(--color-text)';
    let weight = 400;
    if (text.startsWith('"')) color = 'var(--color-healthy)';
    else if (/^-?\d+$/.test(text) || text === 'true' || text === 'false')
      color = 'var(--color-verified)';
    else if (KEYWORDS.has(text)) color = 'var(--color-text-3)';
    else if (FUNCTIONS.has(text)) color = 'var(--color-verified)';
    else if (FIELDS.has(text)) weight = 500;
    else if (/^[A-Za-z_]/.test(text)) color = 'var(--color-blocked-text)';
    else if (/\S/.test(text)) color = 'var(--color-text-3)';
    tokens.push({ text, color, weight });
  }
  return tokens;
}
