// Traefik's routers and services for development and browser tests: one
// docker router per mock host (two for the API, one server down), matched
// the same way as the real API's answers.

import type { TraefikApi } from '../gateway/traefik.ts';
import { matchRoutes } from '../gateway/traefik.ts';
import { MOCK_HOSTS } from './mock-data.ts';

export function createMockTraefik(): TraefikApi {
  const routers = MOCK_HOSTS.flatMap(({ host }, i) => {
    const name = host.split('.')[0] ?? host;
    const base = {
      provider: 'docker',
      status: 'enabled',
      entryPoints: ['websecure'],
      middlewares: name === 'auth' ? ['ratelimit@docker'] : [],
      tls: { certResolver: 'le' },
    };
    return [
      {
        protocol: 'http' as const,
        router: {
          ...base,
          name: `${name}@docker`,
          rule: `Host(\`${host}\`)`,
          service: name,
          priority: 10 + i,
        },
      },
      ...(name === 'api'
        ? [
            {
              protocol: 'http' as const,
              router: {
                ...base,
                name: 'api-v2@docker',
                rule: `Host(\`${host}\`) && PathPrefix(\`/v2\`)`,
                service: 'api-v2',
                priority: 100,
              },
            },
          ]
        : []),
    ];
  });
  const services = new Map(
    [...MOCK_HOSTS.map(({ host }) => host.split('.')[0] ?? host), 'api-v2'].map(
      (name, i) => {
        const servers = [
          `http://172.18.0.${10 + i}:8080`,
          ...(name === 'api' ? [`http://172.18.0.${40 + i}:8080`] : []),
        ];
        return [
          `http:${name}@docker`,
          {
            name: `${name}@docker`,
            status: 'enabled',
            type: 'loadbalancer',
            loadBalancer: { servers: servers.map((url) => ({ url })) },
            serverStatus: Object.fromEntries(
              servers.map((url, j) => [url, j === 1 ? 'DOWN' : 'UP']),
            ),
          },
        ] as const;
      },
    ),
  );
  return {
    routes: (host) => Promise.resolve(matchRoutes(host, routers, services)),
  };
}
