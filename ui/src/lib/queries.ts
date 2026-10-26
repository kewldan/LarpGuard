// Server state: one hook per console endpoint, with polling where the
// screen is live, and mutations that refresh what they change.

import {
  keepPreviousData,
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query';
import { useSyncExternalStore } from 'react';
import {
  attackSchema,
  auditSchema,
  type CandidateRange,
  candidatesSchema,
  crawlersSchema,
  type EnableAttack,
  type FingerprintKind,
  fingerprintsSchema,
  gatewayConfigSchema,
  hostsSchema,
  limitsSchema,
  listEntrySchema,
  listsSchema,
  type NewListEntry,
  overviewSchema,
  passkeyListSchema,
  type ReadinessRange,
  type RequestFilter,
  type RuleTestRequest,
  readinessSchema,
  reloadResultSchema,
  requestDetailSchema,
  requestPageSchema,
  ruleCheckSchema,
  rulesSchema,
  ruleTestResultSchema,
  type SetMode,
  type SettingsChange,
  searchSchema,
  settingsDiffSchema,
  settingsHistorySchema,
  settingsSchema,
  statusSchema,
  type UpdateListEntry,
  type UserCredentials,
  userCredentialsSchema,
  userListSchema,
} from '../../shared/api.ts';

import type { Range, Role } from '../../shared/domain.ts';
import { getJson, send, sendJson } from './api.ts';
import { addPasskey } from './passkeys.ts';

export const keys = {
  status: ['status'] as const,
  config: ['config'] as const,
  overview: (range: Range) => ['overview', range] as const,
  requests: (filter: RequestFilter) => ['requests', filter] as const,
  request: (id: string) => ['request', id] as const,
  fingerprints: (kind: FingerprintKind, q: string) =>
    ['fingerprints', kind, q] as const,
  candidates: (range: CandidateRange) => ['candidates', range] as const,
  rules: ['rules'] as const,
  lists: ['lists'] as const,
  limits: ['limits'] as const,
  hosts: ['hosts'] as const,
  // Under `hosts`: a mode change refreshes it too.
  readiness: (host: string, range: ReadinessRange) =>
    ['hosts', 'readiness', host, range] as const,
  crawlers: ['crawlers'] as const,
  attack: ['attack'] as const,
  audit: ['audit'] as const,
  search: (q: string) => ['search', q] as const,
  passkeys: ['passkeys'] as const,
  users: ['users'] as const,
  settings: ['settings'] as const,
  settingsHistory: ['settings', 'history'] as const,
};

const LIVE = 5000;

export function useStatus() {
  return useQuery({
    queryKey: keys.status,
    queryFn: ({ signal }) =>
      getJson(statusSchema, '/api/status', undefined, signal),
    refetchInterval: LIVE,
  });
}

export function useGatewayConfig() {
  return useQuery({
    queryKey: keys.config,
    queryFn: ({ signal }) =>
      getJson(gatewayConfigSchema, '/api/config', undefined, signal),
    staleTime: 30_000,
  });
}

export function useOverview(range: Range) {
  return useQuery({
    queryKey: keys.overview(range),
    queryFn: ({ signal }) =>
      getJson(overviewSchema, '/api/overview', { range }, signal),
    refetchInterval: range === '15m' || range === '1h' ? 10_000 : 60_000,
    placeholderData: keepPreviousData,
  });
}

// Newest first; each further page continues before the last row.
export function useRequests(filter: RequestFilter, live: boolean) {
  return useInfiniteQuery({
    queryKey: keys.requests(filter),
    queryFn: ({ signal, pageParam }) =>
      getJson(
        requestPageSchema,
        '/api/requests',
        {
          ...(Object.fromEntries(
            Object.entries(filter).map(([k, v]) => [
              k,
              Array.isArray(v) ? v.join(',') : v,
            ]),
          ) as Record<string, string | number | undefined>),
          before: pageParam,
        },
        signal,
      ),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) =>
      last.rows.length === (filter.limit ?? 100)
        ? last.rows[last.rows.length - 1]?.ts
        : undefined,
    refetchInterval: live ? LIVE : false,
    placeholderData: keepPreviousData,
  });
}

export function useRequestDetail(
  id: string | undefined,
  ts: number | undefined,
) {
  return useQuery({
    queryKey: keys.request(id ?? ''),
    queryFn: ({ signal }) =>
      getJson(
        requestDetailSchema,
        `/api/requests/${encodeURIComponent(id ?? '')}`,
        { ts },
        signal,
      ),
    enabled: id !== undefined && ts !== undefined,
    staleTime: 60_000,
  });
}

export function useFingerprints(kind: FingerprintKind, q: string) {
  return useQuery({
    queryKey: keys.fingerprints(kind, q),
    queryFn: ({ signal }) =>
      getJson(fingerprintsSchema, '/api/fingerprints', { kind, q }, signal),
    placeholderData: keepPreviousData,
    refetchInterval: 60_000,
  });
}

export function useCandidates(range: CandidateRange) {
  return useQuery({
    queryKey: keys.candidates(range),
    queryFn: ({ signal }) =>
      getJson(
        candidatesSchema,
        '/api/fingerprints/candidates',
        { range },
        signal,
      ),
    placeholderData: keepPreviousData,
    staleTime: 5 * 60_000,
  });
}

export function useRules() {
  return useQuery({
    queryKey: keys.rules,
    queryFn: ({ signal }) =>
      getJson(rulesSchema, '/api/rules', undefined, signal),
    refetchInterval: 30_000,
  });
}

export function useRuleCheck() {
  return useMutation({
    mutationFn: (draft: RuleTestRequest) =>
      sendJson(ruleCheckSchema, 'POST', '/api/rules/check', draft),
  });
}

export function useRuleTest() {
  return useMutation({
    mutationFn: (draft: RuleTestRequest) =>
      sendJson(ruleTestResultSchema, 'POST', '/api/rules/test', draft),
  });
}

export function useLists() {
  return useQuery({
    queryKey: keys.lists,
    queryFn: ({ signal }) =>
      getJson(listsSchema, '/api/lists', undefined, signal),
    refetchInterval: 15_000,
  });
}

export function useLimits() {
  return useQuery({
    queryKey: keys.limits,
    queryFn: ({ signal }) =>
      getJson(limitsSchema, '/api/limits', undefined, signal),
    refetchInterval: 3000,
  });
}

export function useHosts() {
  return useQuery({
    queryKey: keys.hosts,
    queryFn: ({ signal }) =>
      getJson(hostsSchema, '/api/hosts', undefined, signal),
    refetchInterval: 15_000,
  });
}

export function useReadiness(host: string, range: ReadinessRange) {
  return useQuery({
    queryKey: keys.readiness(host, range),
    queryFn: ({ signal }) =>
      getJson(readinessSchema, '/api/hosts/readiness', { host, range }, signal),
    placeholderData: keepPreviousData,
    staleTime: 60_000,
  });
}

export function useCrawlers() {
  return useQuery({
    queryKey: keys.crawlers,
    queryFn: ({ signal }) =>
      getJson(crawlersSchema, '/api/crawlers', undefined, signal),
    refetchInterval: 60_000,
  });
}

// The last minute of request rates seen by the attack screen's polls
// (busiest host, else all traffic), kept outside React.
const attackRates: number[] = [];
const attackRateListeners = new Set<() => void>();
let attackRatesSnapshot: readonly number[] = [];

export function useAttack() {
  return useQuery({
    queryKey: keys.attack,
    queryFn: async ({ signal }) => {
      const data = await getJson(
        attackSchema,
        '/api/attack',
        undefined,
        signal,
      );
      const rate = data.busiest?.rps ?? data.rps;
      if (rate !== null) {
        attackRates.push(rate);
        if (attackRates.length > 30) attackRates.shift();
        attackRatesSnapshot = [...attackRates];
        for (const listener of attackRateListeners) listener();
      }
      return data;
    },
    refetchInterval: 2000,
  });
}

export function useAttackRates(): readonly number[] {
  return useSyncExternalStore(
    (listener) => {
      attackRateListeners.add(listener);
      return () => attackRateListeners.delete(listener);
    },
    () => attackRatesSnapshot,
  );
}

export function useAudit() {
  return useQuery({
    queryKey: keys.audit,
    queryFn: ({ signal }) =>
      getJson(auditSchema, '/api/audit', undefined, signal),
    refetchInterval: 15_000,
  });
}

export function usePasskeys() {
  return useQuery({
    queryKey: keys.passkeys,
    queryFn: ({ signal }) =>
      getJson(passkeyListSchema, '/api/passkeys', undefined, signal),
  });
}

export function useUsers(enabled: boolean) {
  return useQuery({
    queryKey: keys.users,
    queryFn: ({ signal }) =>
      getJson(userListSchema, '/api/users', undefined, signal),
    enabled,
  });
}

type Confirm = { password: string; totp: string };

// Each answers with the new user's credentials, shown once (null when
// there are none to show).
export function useUserChange() {
  return useChange(
    async (
      change:
        | { kind: 'add'; name: string; role: Role; confirm: Confirm }
        | { kind: 'role'; name: string; role: Role; confirm: Confirm }
        | { kind: 'reset'; name: string; confirm: Confirm }
        | { kind: 'remove'; name: string; confirm: Confirm },
    ): Promise<UserCredentials | null> => {
      const path = `/api/users/${encodeURIComponent(change.name)}`;
      switch (change.kind) {
        case 'add':
          return sendJson(userCredentialsSchema, 'POST', '/api/users', {
            name: change.name,
            role: change.role,
            confirm: change.confirm,
          });
        case 'role':
          await send('PATCH', path, {
            role: change.role,
            confirm: change.confirm,
          });
          return null;
        case 'reset':
          return sendJson(
            userCredentialsSchema,
            'POST',
            `${path}/credentials`,
            {
              confirm: change.confirm,
            },
          );
        case 'remove':
          await send('DELETE', path, { confirm: change.confirm });
          return null;
      }
    },
    [keys.users, keys.audit],
  );
}

export function useSearch(q: string) {
  return useQuery({
    queryKey: keys.search(q),
    queryFn: ({ signal }) =>
      getJson(searchSchema, '/api/search', { q }, signal),
    enabled: q.trim().length > 0,
    staleTime: 10_000,
    placeholderData: keepPreviousData,
  });
}

export function useSettings(enabled = true) {
  return useQuery({
    queryKey: keys.settings,
    queryFn: ({ signal }) =>
      getJson(settingsSchema, '/api/settings', undefined, signal),
    staleTime: 10_000,
    enabled,
  });
}

export function useSettingsHistory() {
  return useQuery({
    queryKey: keys.settingsHistory,
    queryFn: ({ signal }) =>
      getJson(
        settingsHistorySchema,
        '/api/settings/history',
        undefined,
        signal,
      ),
  });
}

// A dry run: what a change would do, or why the gateway refuses it.
export function useValidateSettings() {
  return useMutation({
    mutationFn: (change: SettingsChange) =>
      sendJson(settingsDiffSchema, 'POST', '/api/settings/validate', change),
  });
}

// --- Changes -----------------------------------------------------------------

function useChange<T, R>(
  run: (input: T) => Promise<R>,
  refresh: readonly (readonly unknown[])[],
) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: run,
    onSettled: async () => {
      await Promise.all([
        ...refresh.map((key) => client.invalidateQueries({ queryKey: key })),
        client.invalidateQueries({ queryKey: keys.audit }),
        client.invalidateQueries({ queryKey: keys.status }),
      ]);
    },
  });
}

export function useAddListEntry() {
  return useChange(
    (entry: NewListEntry) =>
      sendJson(listEntrySchema, 'POST', '/api/lists', entry),
    [keys.lists],
  );
}

export function useUpdateListEntry() {
  return useChange(
    ({ id, patch }: { id: number; patch: UpdateListEntry }) =>
      sendJson(listEntrySchema, 'PATCH', `/api/lists/${id}`, patch),
    [keys.lists],
  );
}

export function useRemoveListEntry() {
  return useChange(
    (id: number) => send('DELETE', `/api/lists/${id}`),
    [keys.lists],
  );
}

export function useSetMode() {
  return useChange(
    (change: SetMode) => send('POST', '/api/hosts/mode', change),
    [keys.hosts, ['overview']],
  );
}

export function useClearMode() {
  return useChange(
    (host: string) =>
      send('DELETE', `/api/hosts/mode/${encodeURIComponent(host)}`),
    [keys.hosts, ['overview']],
  );
}

export function useEnableAttack() {
  return useChange(
    (change: EnableAttack) => send('POST', '/api/attack', change),
    [keys.attack],
  );
}

export function useDisableAttack() {
  return useChange(
    (host: string) => send('DELETE', `/api/attack/${encodeURIComponent(host)}`),
    [keys.attack],
  );
}

export function useReload() {
  return useChange(
    () => sendJson(reloadResultSchema, 'POST', '/api/reload'),
    [keys.rules, keys.config, keys.limits],
  );
}

export function useRevert() {
  return useChange(
    (id: string) => send('POST', `/api/audit/${encodeURIComponent(id)}/revert`),
    [keys.lists, keys.hosts, keys.attack, keys.settings, keys.config],
  );
}

// Everything that shows the configuration.
const SETTINGS_VIEWS = [
  keys.settings,
  keys.config,
  keys.rules,
  keys.limits,
  keys.hosts,
  keys.crawlers,
] as const;

export function useApplySettings() {
  return useChange(
    (change: SettingsChange) =>
      sendJson(settingsDiffSchema, 'POST', '/api/settings', change),
    SETTINGS_VIEWS,
  );
}

export function useRollbackSettings() {
  return useChange(
    (input: { revision: string; base_revision: string }) =>
      sendJson(settingsDiffSchema, 'POST', '/api/settings/rollback', input),
    SETTINGS_VIEWS,
  );
}

export function useAddPasskey() {
  return useChange(addPasskey, [keys.passkeys]);
}

export function useRemovePasskey() {
  return useChange(
    (id: string) => send('DELETE', `/api/passkeys/${encodeURIComponent(id)}`),
    [keys.passkeys],
  );
}
