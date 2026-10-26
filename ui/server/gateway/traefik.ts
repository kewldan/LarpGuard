// Traefik's own API (read-only, on loopback: `api.insecure` on a
// 127.0.0.1 entrypoint, deploy/traefik.yml): which routers serve a host,
// their entrypoints, TLS options and middlewares, and the servers behind
// their services with Traefik's health status. The gateway does not know
// any of this; it only forwards to Traefik.

import { z } from 'zod';

import type { TraefikRoute } from '../../shared/api.ts';

const TIMEOUT_MS = 3000;
const PER_PAGE = 500;
const MAX_PAGES = 20;

const routerSchema = z.looseObject({
  name: z.string(),
  rule: z.string().default(''),
  service: z.string().default(''),
  provider: z.string().default(''),
  status: z.string().default(''),
  entryPoints: z.array(z.string()).default([]),
  middlewares: z.array(z.string()).default([]),
  priority: z.number().optional(),
  tls: z
    .looseObject({
      options: z.string().optional(),
      certResolver: z.string().optional(),
      passthrough: z.boolean().optional(),
    })
    .optional(),
});
type Router = z.infer<typeof routerSchema>;

const serviceSchema = z.looseObject({
  name: z.string(),
  status: z.string().default(''),
  type: z.string().default(''),
  loadBalancer: z
    .looseObject({
      servers: z
        .array(
          z.looseObject({
            url: z.string().optional(),
            address: z.string().optional(),
          }),
        )
        .default([]),
    })
    .optional(),
  // HTTP health per server URL ("UP"/"DOWN"), with a health check.
  serverStatus: z.record(z.string(), z.string()).optional(),
});
type Service = z.infer<typeof serviceSchema>;

export interface TraefikApi {
  // Routers matching the host, with their services; throws when Traefik's
  // API cannot be read.
  routes(host: string): Promise<TraefikRoute[]>;
}

// Host names in a rule: Host(`a`, `b`), HostSNI(`a`), and HostRegexp
// patterns (tested against the host).
export function ruleMatchesHost(rule: string, host: string): boolean {
  const name = host.toLowerCase();
  for (const match of rule.matchAll(
    /\b(HostSNI|HostRegexp|Host)\(([^)]*)\)/g,
  )) {
    const values = [...(match[2] ?? '').matchAll(/`([^`]*)`|"([^"]*)"/g)].map(
      (value) => (value[1] ?? value[2] ?? '').toLowerCase(),
    );
    for (const value of values) {
      if (match[1] === 'HostRegexp') {
        try {
          if (new RegExp(value, 'i').test(name)) return true;
        } catch {
          // Not a pattern this engine reads: no match.
        }
      } else if (value === name || value === '*') {
        return true;
      }
    }
  }
  return false;
}

// "svc" means "svc@<the router's provider>".
function qualified(service: string, provider: string): string {
  return service.includes('@') || !provider
    ? service
    : `${service}@${provider}`;
}

export function matchRoutes(
  host: string,
  routers: { protocol: 'http' | 'tcp'; router: Router }[],
  services: Map<string, Service>,
): TraefikRoute[] {
  return routers
    .filter(({ router }) => ruleMatchesHost(router.rule, host))
    .map(({ protocol, router }) => {
      const name = qualified(router.service, router.provider);
      const service = services.get(`${protocol}:${name}`);
      return {
        protocol,
        name: router.name,
        rule: router.rule,
        status: router.status,
        entrypoints: router.entryPoints,
        middlewares: router.middlewares,
        tls_options: router.tls?.options ?? null,
        passthrough: router.tls?.passthrough === true,
        service: name,
        service_status: service?.status ?? null,
        servers: (service?.loadBalancer?.servers ?? []).map((server) => {
          const target = server.url ?? server.address ?? '';
          return {
            target,
            status: service?.serverStatus?.[target] ?? null,
          };
        }),
      };
    });
}

async function pages<T>(
  baseUrl: string,
  path: string,
  schema: z.ZodType<T>,
): Promise<T[]> {
  const out: T[] = [];
  let page = 1;
  for (let i = 0; i < MAX_PAGES; i += 1) {
    // Relative to the base, so a prefix in it (a proxy path) is kept.
    const url = new URL(
      path.replace(/^\//, ''),
      baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`,
    );
    url.searchParams.set('per_page', String(PER_PAGE));
    url.searchParams.set('page', String(page));
    const response = await fetch(url, {
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!response.ok) {
      throw new Error(`Traefik API ${path}: HTTP ${response.status}`);
    }
    out.push(...z.array(schema).parse(await response.json()));
    const next = Number(response.headers.get('x-next-page'));
    if (!Number.isInteger(next) || next <= page) break;
    page = next;
  }
  return out;
}

export function createTraefikClient(baseUrl: string): TraefikApi {
  return {
    async routes(host) {
      const [httpRouters, tcpRouters, httpServices, tcpServices] =
        await Promise.all([
          pages(baseUrl, '/api/http/routers', routerSchema),
          pages(baseUrl, '/api/tcp/routers', routerSchema),
          pages(baseUrl, '/api/http/services', serviceSchema),
          pages(baseUrl, '/api/tcp/services', serviceSchema),
        ]);
      const services = new Map<string, Service>([
        ...httpServices.map(
          (service) => [`http:${service.name}`, service] as const,
        ),
        ...tcpServices.map(
          (service) => [`tcp:${service.name}`, service] as const,
        ),
      ]);
      return matchRoutes(
        host,
        [
          ...httpRouters.map((router) => ({
            protocol: 'http' as const,
            router,
          })),
          ...tcpRouters.map((router) => ({ protocol: 'tcp' as const, router })),
        ],
        services,
      );
    },
  };
}
