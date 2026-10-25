// A small evaluator of the gateway's rule language for the development
// mock only (the real one is src/score/rules.cc and answers
// POST /rules/test). Same grammar and field types; header(),
// has_header(), cookie(), has_cookie(), query() and has_query() see empty
// values, cidr() the event's prefix.

import type { RuleSampleEvent } from '../gateway/admin.ts';

type Type = 'string' | 'int' | 'bool' | 'list';
type Value = string | number | boolean | string[];

const FIELDS: Record<string, Type> = {
  host: 'string',
  method: 'string',
  path: 'string',
  http_version: 'string',
  sni: 'string',
  alpn: 'string',
  ja4: 'string',
  h2_fp: 'string',
  pseudo_order: 'string',
  header_fp: 'string',
  tcp_fp: 'string',
  user_agent: 'string',
  ua_family: 'string',
  ua_engine: 'string',
  ua_os: 'string',
  ua_tool: 'string',
  score: 'int',
  class: 'string',
  reasons: 'list',
  asn: 'int',
  asn_org: 'string',
  asn_country: 'string',
  asn_hosting: 'bool',
  signed_agent: 'string',
  tcp_rtt_ms: 'int',
  handshake_ms: 'int',
};

interface Token {
  kind: 'string' | 'int' | 'ident' | 'op' | 'end';
  text: string;
  position: number;
}

interface Node {
  type: Type;
  references: string[];
  eval: (event: RuleSampleEvent) => Value;
}

export class RuleError extends Error {
  readonly column: number;
  constructor(column: number, message: string) {
    super(`col ${column}: ${message}`);
    this.column = column;
  }
}

function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  for (;;) {
    while (i < input.length && /\s/.test(input[i] ?? '')) i += 1;
    const position = i + 1;
    if (i >= input.length) {
      tokens.push({ kind: 'end', text: '', position });
      return tokens;
    }
    const rest = input.slice(i);
    const string = /^"((?:[^"\\]|\\.)*)"/.exec(rest);
    const number = /^-?\d+/.exec(rest);
    const ident = /^[A-Za-z_]\w*/.exec(rest);
    const op = /^(==|!=|<=|>=|[<>~()[\],])/.exec(rest);
    if (rest.startsWith('"')) {
      if (!string) throw new RuleError(position, 'unterminated string');
      tokens.push({
        kind: 'string',
        text: (string[1] ?? '').replace(/\\(.)/g, '$1'),
        position,
      });
      i += string[0].length;
    } else if (number) {
      tokens.push({ kind: 'int', text: number[0], position });
      i += number[0].length;
    } else if (ident) {
      tokens.push({ kind: 'ident', text: ident[0], position });
      i += ident[0].length;
    } else if (op) {
      tokens.push({ kind: 'op', text: op[0], position });
      i += op[0].length;
    } else {
      throw new RuleError(position, `unexpected '${rest[0] ?? ''}'`);
    }
  }
}

function field(event: RuleSampleEvent, name: string): Value {
  switch (name) {
    case 'path':
      return event.path;
    case 'class':
      return event.class;
    case 'ua_tool':
      return (
        /curl|python|go-http|wget/i.exec(event.user_agent)?.[0].toLowerCase() ??
        ''
      );
    case 'asn_hosting':
      return [64496, 64497, 64500].includes(event.asn);
    case 'tcp_rtt_ms':
      return event.tcp_rtt_us === null
        ? -1
        : Math.floor(event.tcp_rtt_us / 1000);
    case 'handshake_ms':
      return event.handshake_us === null
        ? -1
        : Math.floor(event.handshake_us / 1000);
    default: {
      const value = (event as unknown as Record<string, Value | undefined>)[
        name
      ];
      return (
        value ??
        (FIELDS[name] === 'int' ? 0 : FIELDS[name] === 'bool' ? false : '')
      );
    }
  }
}

function glob(pattern: string, text: string): boolean {
  const regex = new RegExp(
    `^${pattern
      .split('*')
      .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
      .join('.*')}$`,
  );
  return regex.test(text);
}

class Parser {
  private at = 0;
  private readonly tokens: Token[];
  constructor(tokens: Token[]) {
    this.tokens = tokens;
  }
  private peek(): Token {
    return this.tokens[this.at] ?? { kind: 'end', text: '', position: 0 };
  }
  private next(): Token {
    const token = this.peek();
    this.at += 1;
    return token;
  }
  private keyword(word: string): boolean {
    const token = this.peek();
    return token.kind === 'ident' && token.text === word;
  }
  all(): Node {
    const node = this.or();
    if (this.peek().kind !== 'end')
      throw new RuleError(this.peek().position, 'unexpected trailing input');
    if (node.type !== 'bool')
      throw new RuleError(1, `condition must be bool, not ${node.type}`);
    return node;
  }
  private logical(word: 'and' | 'or', operand: () => Node): Node {
    let left = operand();
    while (this.keyword(word)) {
      const position = this.next().position;
      const right = operand();
      if (left.type !== 'bool' || right.type !== 'bool') {
        throw new RuleError(position, 'and/or need bool operands');
      }
      const l = left;
      left = {
        type: 'bool',
        references: [...l.references, ...right.references],
        eval:
          word === 'and'
            ? (e) => Boolean(l.eval(e)) && Boolean(right.eval(e))
            : (e) => Boolean(l.eval(e)) || Boolean(right.eval(e)),
      };
    }
    return left;
  }
  private or(): Node {
    return this.logical('or', () => this.and());
  }
  private and(): Node {
    return this.logical('and', () => this.not());
  }
  private not(): Node {
    if (!this.keyword('not')) return this.compare();
    const position = this.next().position;
    const operand = this.not();
    if (operand.type !== 'bool')
      throw new RuleError(position, 'not needs a bool');
    return {
      type: 'bool',
      references: operand.references,
      eval: (e) => !operand.eval(e),
    };
  }
  private compare(): Node {
    const left = this.operand();
    const token = this.peek();
    const op =
      token.kind === 'op' &&
      ['==', '!=', '<', '<=', '>', '>=', '~'].includes(token.text)
        ? token.text
        : this.keyword('in')
          ? 'in'
          : null;
    if (op === null) return left;
    this.next();
    const right = this.operand();
    const references = [...left.references, ...right.references];
    if (op === 'in') {
      if (left.type !== 'string' || right.type !== 'list')
        throw new RuleError(token.position, 'in needs a string and a list');
      return {
        type: 'bool',
        references,
        eval: (e) =>
          (right.eval(e) as string[]).includes(left.eval(e) as string),
      };
    }
    if (op === '~') {
      if (left.type !== 'string' || right.type !== 'string')
        throw new RuleError(token.position, '~ needs two strings');
      return {
        type: 'bool',
        references,
        eval: (e) => glob(right.eval(e) as string, left.eval(e) as string),
      };
    }
    if (left.type !== right.type)
      throw new RuleError(
        token.position,
        `cannot compare ${left.type} with ${right.type}`,
      );
    if (['<', '<=', '>', '>='].includes(op) && left.type !== 'int')
      throw new RuleError(token.position, `${op} needs two ints`);
    return {
      type: 'bool',
      references,
      eval: (e) => {
        const a = left.eval(e);
        const b = right.eval(e);
        switch (op) {
          case '==':
            return a === b;
          case '!=':
            return a !== b;
          case '<':
            return (a as number) < (b as number);
          case '<=':
            return (a as number) <= (b as number);
          case '>':
            return (a as number) > (b as number);
          default:
            return (a as number) >= (b as number);
        }
      },
    };
  }
  private operand(): Node {
    const token = this.next();
    if (token.kind === 'string')
      return { type: 'string', references: [], eval: () => token.text };
    if (token.kind === 'int')
      return { type: 'int', references: [], eval: () => Number(token.text) };
    if (token.kind === 'op' && token.text === '(') {
      const inner = this.or();
      if (this.next().text !== ')')
        throw new RuleError(this.peek().position, "expected ')'");
      return inner;
    }
    if (token.kind === 'op' && token.text === '[') {
      const items: string[] = [];
      while (this.peek().text !== ']') {
        const item = this.next();
        if (item.kind !== 'string')
          throw new RuleError(item.position, 'lists hold strings');
        items.push(item.text);
        if (this.peek().text === ',') this.next();
      }
      this.next();
      return { type: 'list', references: [], eval: () => items };
    }
    if (token.kind === 'ident') {
      if (token.text === 'true' || token.text === 'false') {
        return {
          type: 'bool',
          references: [],
          eval: () => token.text === 'true',
        };
      }
      if (
        [
          'header',
          'has_header',
          'cookie',
          'has_cookie',
          'query',
          'has_query',
          'cidr',
        ].includes(token.text)
      ) {
        if (this.next().text !== '(')
          throw new RuleError(token.position, "expected '('");
        const argument = this.next();
        if (argument.kind !== 'string')
          throw new RuleError(argument.position, 'expected a string literal');
        if (this.next().text !== ')')
          throw new RuleError(argument.position, "expected ')'");
        const name = `${token.text}()`;
        if (token.text === 'cidr') {
          const network = argument.text.split('/')[0] ?? '';
          const stem = network.split('.').slice(0, 3).join('.');
          return {
            type: 'bool',
            references: [name],
            eval: (e) => e.ip_prefix.startsWith(stem),
          };
        }
        return token.text.startsWith('has_')
          ? { type: 'bool', references: [name], eval: () => false }
          : { type: 'string', references: [name], eval: () => '' };
      }
      const type = FIELDS[token.text];
      if (!type)
        throw new RuleError(token.position, `unknown name '${token.text}'`);
      return {
        type,
        references: [token.text],
        eval: (e) => field(e, token.text),
      };
    }
    throw new RuleError(token.position, 'expected an operand');
  }
}

export function compileRule(text: string): {
  references: string[];
  matches: (event: RuleSampleEvent) => boolean;
} {
  const node = new Parser(tokenize(text)).all();
  return {
    references: [...new Set(node.references)].sort(),
    matches: (event) => Boolean(node.eval(event)),
  };
}
