import { describe, expect, it } from 'vitest';

import { gatewayChallengeUrl, isGatewayChallenge } from './api.ts';

describe('gateway challenge', () => {
  it('recognizes the gateway answer, not the BFF errors', () => {
    expect(
      isGatewayChallenge({
        error: 'challenge_required',
        challenge: '/__bs/challenge?r=%2Fapi%2Fstatus',
      }),
    ).toBe(true);
    expect(isGatewayChallenge({ error: 'forbidden' })).toBe(false);
    expect(isGatewayChallenge(null)).toBe(false);
    expect(isGatewayChallenge('challenge_required')).toBe(false);
  });

  it('returns to the current screen, not to the API path', () => {
    const url = gatewayChallengeUrl({
      pathname: '/requests',
      search: '?host=shop.example.com&range=1h',
    } as Location);
    expect(url).toBe(
      '/__bs/challenge?r=%2Frequests%3Fhost%3Dshop.example.com%26range%3D1h',
    );
  });
});
