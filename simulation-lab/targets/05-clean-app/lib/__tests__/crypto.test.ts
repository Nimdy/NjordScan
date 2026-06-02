import { describe, expect, it } from 'vitest';

import { generateId, safeEqual, sha256 } from '../crypto';

describe('crypto helpers', () => {
  it('generates unique, sufficiently long ids', () => {
    const a = generateId();
    const b = generateId();
    expect(a).not.toEqual(b);
    expect(a.length).toBeGreaterThanOrEqual(40);
  });

  it('produces a stable 64-char sha-256 hex digest', () => {
    const digest = sha256('hello world');
    expect(digest).toHaveLength(64);
    expect(sha256('hello world')).toEqual(digest);
  });

  it('compares equal strings in constant time and rejects mismatches', () => {
    expect(safeEqual('matching-value', 'matching-value')).toBe(true);
    expect(safeEqual('one', 'two')).toBe(false);
    expect(safeEqual('short', 'longer-value')).toBe(false);
  });
});
