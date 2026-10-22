import { describe, it, expect } from 'vitest';
import { getDefaultClientId } from '../src/cloud-config.js';

// SOV-01 : le client OAuth par défaut doit être l'app registration Ixtria, jamais celle de Softeria.
describe('getDefaultClientId', () => {
  it('returns the Ixtria app registration for the global cloud', () => {
    expect(getDefaultClientId('global')).toBe(
      'bfe24719-6803-4c88-be5e-acfd18655a54',
    );
    expect(getDefaultClientId()).toBe('bfe24719-6803-4c88-be5e-acfd18655a54');
  });

  it('never falls back to the upstream Softeria app registration', () => {
    expect(getDefaultClientId('global')).not.toBe(
      '084a3e9f-a9f4-43f7-89f9-d229cf97853e',
    );
  });
});
