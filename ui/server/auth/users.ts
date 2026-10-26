// Console users: those in console.yaml, which the console never rewrites,
// and those an admin manages from the console, kept in `users_file` (JSON,
// mode 0600, written through a temporary file and rename). A name exists
// once: console.yaml's users cannot be shadowed or changed from here.

import { randomBytes } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from 'node:fs';

import { z } from 'zod';

import { roleSchema } from '../../shared/api.ts';
import type { Role } from '../../shared/domain.ts';
import type { ConsoleUser } from '../config.ts';

const storedUserSchema = z.object({
  name: z.string().regex(/^[A-Za-z0-9._-]{1,64}$/),
  role: roleSchema,
  password: z.string().startsWith('scrypt$'),
  totp_secret: z.string().regex(/^[A-Z2-7]{16,}=*$/),
  created_at: z.number(),
  created_by: z.string(),
});
export type StoredUser = z.infer<typeof storedUserSchema>;

export interface UserView {
  name: string;
  role: Role;
  // console.yaml or this console.
  source: 'config' | 'console';
  created_at: number | null;
  created_by: string | null;
}

// A password handed out once: 20 characters from a 64-symbol alphabet
// (120 bits), above the 12-character minimum of hash-password.
export function newPassword(): string {
  return randomBytes(15).toString('base64url');
}

export class UserDirectory {
  private readonly configured: Map<string, ConsoleUser>;
  private readonly path: string | null;
  private managed = new Map<string, StoredUser>();

  // `path` null: users come from console.yaml only (no management).
  constructor(configured: readonly ConsoleUser[], path: string | null) {
    this.configured = new Map(configured.map((user) => [user.name, user]));
    this.path = path;
    if (path !== null && existsSync(path)) {
      const stored = z
        .array(storedUserSchema)
        .parse(JSON.parse(readFileSync(path, 'utf8')));
      for (const user of stored) {
        // console.yaml wins: a file user with its name is ignored.
        if (!this.configured.has(user.name)) this.managed.set(user.name, user);
      }
    }
  }

  get editable(): boolean {
    return this.path !== null;
  }

  get(name: string): ConsoleUser | undefined {
    return this.configured.get(name) ?? this.managed.get(name);
  }

  isManaged(name: string): boolean {
    return this.managed.has(name);
  }

  list(): UserView[] {
    return [
      ...[...this.configured.values()].map((user) => ({
        name: user.name,
        role: user.role,
        source: 'config' as const,
        created_at: null,
        created_by: null,
      })),
      ...[...this.managed.values()].map((user) => ({
        name: user.name,
        role: user.role,
        source: 'console' as const,
        created_at: user.created_at,
        created_by: user.created_by,
      })),
    ];
  }

  add(user: StoredUser): void {
    if (this.get(user.name)) throw new Error(`user ${user.name} exists`);
    this.change(() => {
      this.managed.set(user.name, user);
    });
  }

  setRole(name: string, role: Role): void {
    const user = this.managedUser(name);
    this.change(() => {
      this.managed.set(name, { ...user, role });
    });
  }

  setCredentials(name: string, password: string, totpSecret: string): void {
    const user = this.managedUser(name);
    this.change(() => {
      this.managed.set(name, { ...user, password, totp_secret: totpSecret });
    });
  }

  remove(name: string): void {
    this.managedUser(name);
    this.change(() => {
      this.managed.delete(name);
    });
  }

  private managedUser(name: string): StoredUser {
    const user = this.managed.get(name);
    if (!user) throw new Error(`user ${name} is not managed here`);
    return user;
  }

  // Applies `edit` and writes the file; on a write error the change is
  // undone and the error thrown.
  private change(edit: () => void): void {
    if (this.path === null) throw new Error('users_file is not set');
    const before = new Map(this.managed);
    edit();
    try {
      const temporary = `${this.path}.tmp`;
      writeFileSync(
        temporary,
        `${JSON.stringify([...this.managed.values()], null, 2)}\n`,
        { mode: 0o600 },
      );
      chmodSync(temporary, 0o600);
      renameSync(temporary, this.path);
    } catch (error) {
      this.managed = before;
      throw error;
    }
  }
}
