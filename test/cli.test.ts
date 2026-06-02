import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { parseArgs } from '../src/cli.js';

vi.mock('commander', () => {
  // Vitest 4 requires the mocked Command to be a real constructor (i.e.
  // `new Command()` must call a function reference, not an arrow). Using a
  // class keyword satisfies the `[[Construct]]` internal method.
  class MockCommand {
    name = vi.fn().mockReturnThis();
    description = vi.fn().mockReturnThis();
    version = vi.fn().mockReturnThis();
    option = vi.fn().mockReturnThis();
    parse = vi.fn();
    opts = vi.fn().mockReturnValue({ file: 'test.xlsx' });
  }
  return { Command: MockCommand };
});

vi.mock('../src/auth.js', () => {
  return {
    default: vi.fn().mockImplementation(() => ({
      getToken: vi.fn().mockResolvedValue('mock-token'),
      logout: vi.fn().mockResolvedValue(true),
    })),
  };
});
vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
vi.spyOn(process, 'exit').mockImplementation(() => {});

describe('CLI Module', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('parseArgs', () => {
    it('should return command options', () => {
      const result = parseArgs();
      expect(result).toEqual({ file: 'test.xlsx' });
    });
  });
});
