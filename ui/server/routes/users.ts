// Users, for admins (ADR-017, п. 4): everyone who can sign in, and the
// users managed here (users_file). console.yaml's users are read-only.
// Every change asks for the admin's own password and code again, ends the
// user's sessions, is audited, and never applies to the admin's own
// account (no locking yourself out).
//
// GET    /api/users                     users with their passkeys and sessions
// POST   /api/users                     add a user: credentials shown once
// PATCH  /api/users/:name               change the role
// POST   /api/users/:name/credentials   new password and TOTP secret
// DELETE /api/users/:name               remove a user (and its passkeys)

import type { Context, Hono } from 'hono';
import type { z } from 'zod';

import {
  changeUserSchema,
  confirmUserSchema,
  newUserSchema,
  userCredentialsSchema,
  userListSchema,
} from '../../shared/api.ts';
import type { Role } from '../../shared/domain.ts';
import { hashPassword } from '../auth/password.ts';
import type { SignInGuard } from '../auth/signin.ts';
import { newTotpSecret, otpauthUri } from '../auth/totp.ts';
import { newPassword, type UserDirectory } from '../auth/users.ts';
import type { AppEnv } from '../deps.ts';
import { fail, jsonBody, parseOr400, send } from '../http.ts';
import { requireRole } from '../roles.ts';

export interface UsersContext {
  guard: SignInGuard;
  users: UserDirectory;
  network: (c: Context<AppEnv>) => string;
}

type Confirm = z.infer<typeof confirmUserSchema>['confirm'];

// The admin's own password and code, under the sign-in limiter.
async function reauth(
  c: Context<AppEnv>,
  ctx: UsersContext,
  confirm: Confirm,
  doing: string,
): Promise<void> {
  const deps = c.get('deps');
  const session = c.get('session');
  const now = deps.now();
  const network = ctx.network(c);
  const keys = [`user:${session.user}`, `net:${network}`];
  const locked = ctx.guard.lockedFor(keys, now);
  if (locked > 0) {
    fail(
      429,
      `too many failed sign-ins, try again in ${Math.ceil(locked / 60_000)} min`,
    );
  }
  const admin = ctx.users.get(session.user);
  const result = await ctx.guard.check(
    admin,
    confirm.password,
    confirm.totp,
    now,
  );
  if (!admin || result !== 'ok') {
    const lockedNow = ctx.guard.fail(keys, now);
    deps.audit.append({
      kind: 'auth',
      actor: session.user,
      what: `Failed check before ${doing}${lockedNow ? ', locked 5 min' : ''}`,
      facts: [
        ['From', network],
        [
          'Reason',
          result === 'replay' ? 'code already used' : 'wrong credentials',
        ],
      ],
    });
    fail(403, 'wrong password or code');
  }
  ctx.guard.succeed(keys);
}

// A user this admin may change: managed here, and not themselves.
function target(c: Context<AppEnv>, ctx: UsersContext): string {
  const name = c.req.param('name') ?? '';
  if (!ctx.users.get(name)) fail(404, 'no such user');
  if (name === c.get('session').user) {
    fail(403, 'not your own account (ask another admin)');
  }
  if (!ctx.users.isManaged(name)) {
    fail(409, `${name} is in console.yaml: change it there`);
  }
  return name;
}

async function credentials(name: string, role: Role) {
  const password = newPassword();
  const totpSecret = newTotpSecret();
  return {
    hash: await hashPassword(password),
    shown: {
      name,
      role,
      password,
      totp_secret: totpSecret,
      otpauth: otpauthUri(totpSecret, name),
    },
  };
}

export function registerUsers(app: Hono<AppEnv>, ctx: UsersContext): void {
  app.get('/api/users', requireRole('admin'), (c) => {
    const deps = c.get('deps');
    return send(c, userListSchema, {
      editable: ctx.users.editable,
      users: ctx.users.list().map((user) => ({
        ...user,
        passkeys: deps.passkeys?.forUser(user.name).length ?? 0,
        sessions: deps.sessions.countUser(user.name, deps.now()),
      })),
    });
  });

  app.post('/api/users', requireRole('admin'), async (c) => {
    const deps = c.get('deps');
    const body = parseOr400(newUserSchema, await jsonBody(c));
    if (!ctx.users.editable) fail(409, 'users_file is not set');
    if (ctx.users.get(body.name)) fail(409, `${body.name} exists already`);
    await reauth(c, ctx, body.confirm, `adding user ${body.name}`);
    const made = await credentials(body.name, body.role);
    ctx.users.add({
      name: body.name,
      role: body.role,
      password: made.hash,
      totp_secret: made.shown.totp_secret,
      created_at: deps.now(),
      created_by: c.get('session').user,
    });
    deps.audit.append({
      kind: 'users',
      actor: c.get('session').user,
      what: `Added user ${body.name} (${body.role})`,
      after: { name: body.name, role: body.role },
      facts: [['Credentials', 'shown once to the admin']],
    });
    return send(c, userCredentialsSchema, made.shown, 201);
  });

  app.patch('/api/users/:name', requireRole('admin'), async (c) => {
    const deps = c.get('deps');
    const name = target(c, ctx);
    const body = parseOr400(changeUserSchema, await jsonBody(c));
    await reauth(c, ctx, body.confirm, `changing user ${name}`);
    const before = ctx.users.get(name)?.role;
    ctx.users.setRole(name, body.role);
    // The role is fixed at sign-in: sessions start over with the new one.
    deps.sessions.destroyUser(name);
    deps.audit.append({
      kind: 'users',
      actor: c.get('session').user,
      what: `${name}: role ${before ?? '?'} → ${body.role}`,
      before: { role: before },
      after: { role: body.role },
      facts: [['Sessions', 'ended']],
    });
    return c.body(null, 204);
  });

  app.post('/api/users/:name/credentials', requireRole('admin'), async (c) => {
    const deps = c.get('deps');
    const name = target(c, ctx);
    const body = parseOr400(confirmUserSchema, await jsonBody(c));
    await reauth(c, ctx, body.confirm, `new credentials for ${name}`);
    const role = ctx.users.get(name)?.role ?? 'viewer';
    const made = await credentials(name, role);
    ctx.users.setCredentials(name, made.hash, made.shown.totp_secret);
    deps.sessions.destroyUser(name);
    // Recovering an account: its passkeys may be the lost device.
    const removed = deps.passkeys?.removeUser(name) ?? 0;
    deps.audit.append({
      kind: 'users',
      actor: c.get('session').user,
      what: `New password and code for ${name}`,
      facts: [
        ['Sessions', 'ended'],
        ['Passkeys removed', String(removed)],
      ],
    });
    return send(c, userCredentialsSchema, made.shown);
  });

  app.delete('/api/users/:name', requireRole('admin'), async (c) => {
    const deps = c.get('deps');
    const name = target(c, ctx);
    const body = parseOr400(confirmUserSchema, await jsonBody(c));
    await reauth(c, ctx, body.confirm, `removing user ${name}`);
    const role = ctx.users.get(name)?.role;
    ctx.users.remove(name);
    deps.sessions.destroyUser(name);
    const removed = deps.passkeys?.removeUser(name) ?? 0;
    deps.audit.append({
      kind: 'users',
      actor: c.get('session').user,
      what: `Removed user ${name}`,
      before: { name, role },
      facts: [['Passkeys removed', String(removed)]],
    });
    return c.body(null, 204);
  });
}
