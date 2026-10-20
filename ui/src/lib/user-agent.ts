// What a User-Agent claims, for the explorer's "claims vs observed". The
// gateway's own parser decides verdicts; this only labels the claim.

export interface Claim {
  browser: string;
  os: string;
}

export function parseClaim(userAgent: string): Claim {
  const ua = userAgent;
  if (ua.trim() === '') return { browser: 'empty', os: '' };
  let browser = 'unknown';
  const tool =
    /(curl|wget|python-requests|python-urllib|go-http-client|okhttp|java|node-fetch|axios)\/?([\d.]*)/i.exec(
      ua,
    );
  const edge = /Edg\/(\d+)/.exec(ua);
  const chrome = /(?:HeadlessChrome|Chrome|CriOS)\/(\d+)/.exec(ua);
  const firefox = /(?:Firefox|FxiOS)\/(\d+)/.exec(ua);
  const safari = /Version\/(\d+)[\d.]* .*Safari\//.exec(ua);
  const bot = /([A-Za-z]*bot)\/?([\d.]*)/i.exec(ua);
  if (tool) browser = `${tool[1] ?? ''} ${tool[2] ?? ''}`.trim();
  else if (bot && /compatible;/i.test(ua)) browser = bot[1] ?? 'bot';
  else if (edge) browser = `Edge ${edge[1] ?? ''}`;
  else if (chrome)
    browser = `${ua.includes('HeadlessChrome') ? 'Headless ' : ''}Chrome ${chrome[1] ?? ''}`;
  else if (firefox) browser = `Firefox ${firefox[1] ?? ''}`;
  else if (safari) browser = `Safari ${safari[1] ?? ''}`;
  let os = '';
  if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';
  else if (ua.includes('Android')) os = 'Android';
  else if (/Mac OS X|Macintosh/.test(ua)) os = 'macOS';
  else if (ua.includes('Windows')) os = 'Windows';
  else if (ua.includes('CrOS')) os = 'ChromeOS';
  else if (ua.includes('Linux')) os = 'Linux';
  return { browser, os };
}
