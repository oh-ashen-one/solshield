import { describe, it, expect } from 'vitest';
import { patterns } from '../patterns/index.js';

describe('Patterns', () => {
  it('should have patterns defined', () => {
    expect(patterns).toBeDefined();
    expect(Array.isArray(patterns)).toBe(true);
  });

  it('should have at least 100 patterns', () => {
    expect(patterns.length).toBeGreaterThanOrEqual(100);
  });

  it('each pattern should have required fields', () => {
    for (const pattern of patterns.slice(0, 50)) {
      expect(pattern.id).toBeDefined();
      expect(pattern.id).toMatch(/^SOL\d{3}$/);
      expect(pattern.name).toBeDefined();
      expect(pattern.severity).toMatch(/^(critical|high|medium|low|info)$/);
      expect(typeof pattern.run).toBe('function');
    }
  });

  it('pattern IDs should be unique', () => {
    const ids = patterns.map(p => p.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });
});
