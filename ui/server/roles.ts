// Role checks for routes that change things.

import type { MiddlewareHandler } from 'hono';

import type { Role } from '../shared/domain.ts';
import type { AppEnv } from './deps.ts';
import { fail } from './http.ts';

const ROLE_RANK: Record<Role, number> = { viewer: 0, operator: 1 };

export function requireRole(role: Role): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    if (ROLE_RANK[c.get('session').role] < ROLE_RANK[role]) {
      fail(403, `needs the ${role} role`);
    }
    await next();
  };
}
