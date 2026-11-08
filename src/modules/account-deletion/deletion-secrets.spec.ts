import { ConfigService } from '@nestjs/config';
import { DeletionSecrets } from './deletion-secrets';

function secrets(values: Record<string, string> = {}) {
  return new DeletionSecrets(
    new ConfigService({ ACCOUNT_DELETION_SECRET: 'ab'.repeat(32), ...values }),
  );
}
describe('Account deletion secrets', () => {
  test('a six digit code is bound to its purpose and its individual request', () => {
    const crypto = secrets(),
      code = '000007',
      hash = crypto.hash('code', 'request-a', code);
    expect(hash).toHaveLength(64);
    expect(crypto.matches('code', 'request-a', code, hash)).toBe(true);
    expect(crypto.matches('code', 'request-b', code, hash)).toBe(false);
    expect(crypto.matches('authorization', 'request-a', code, hash)).toBe(
      false,
    );
    expect(crypto.matches('code', 'request-a', '000008', hash)).toBe(false);
    expect(crypto.matches('code', 'request-a', code, 'invalid')).toBe(false);
  });
  test('notification addresses are authenticated encrypted values with distinct nonces', () => {
    const crypto = secrets(),
      value = 'owner@qa.invalid',
      encrypted = crypto.encrypt(value);
    expect(encrypted).not.toContain(value);
    expect(crypto.encrypt(value)).not.toBe(encrypted);
    expect(crypto.decrypt(encrypted)).toBe(value);
    const pieces = encrypted.split('.');
    pieces[2] = Buffer.from('changed').toString('base64url');
    expect(() => crypto.decrypt(pieces.join('.'))).toThrow();
    expect(() =>
      secrets({ ACCOUNT_DELETION_SECRET: 'cd'.repeat(32) }).decrypt(encrypted),
    ).toThrow();
  });
  test.each(['', 'short', 'zz'.repeat(32)])(
    'rejects an unavailable or invalid dedicated secret',
    (key) => {
      expect(() =>
        secrets({ ACCOUNT_DELETION_SECRET: key }).hash('code', 'a', '123456'),
      ).toThrow('no está configurada');
    },
  );
  test.each([
    'JWT_SECRET',
    'JWT_REFRESH_SECRET',
    'ACCOUNT_DELETION_LEDGER_SECRET',
  ])('does not reuse %s', (name) => {
    expect(() =>
      secrets({ [name]: 'ab'.repeat(32) }).hash('code', 'a', '123456'),
    ).toThrow();
  });
});
