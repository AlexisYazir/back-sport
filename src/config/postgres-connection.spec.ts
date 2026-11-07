import { postgresConnectionOptions } from './postgres-connection';

const base =
  'postgresql://qa_user:qa%40password@db.qa.invalid:5544/qa_database';

describe('verified PostgreSQL connection configuration', () => {
  it.each([
    '',
    '?sslmode=require&channel_binding=require',
    '?sslmode=verify-full',
  ])('uses explicit connection fields and strict TLS for %s', (query) => {
    const options = postgresConnectionOptions(base + query, 20);
    expect(options).toMatchObject({
      host: 'db.qa.invalid',
      port: 5544,
      username: 'qa_user',
      password: 'qa@password',
      database: 'qa_database',
      ssl: { rejectUnauthorized: true },
      extra: { connectionLimit: 20, enableChannelBinding: true },
    });
    expect(options).not.toHaveProperty('url');
    expect(options).not.toHaveProperty('connectionString');
    expect(options.extra).not.toHaveProperty('ssl');
    expect(options.ssl).not.toHaveProperty('ca');
    expect(options.ssl).toHaveProperty(
      'checkServerIdentity',
      expect.any(Function),
    );
  });

  it('accepts an explicit private CA without changing verification', () => {
    expect(postgresConnectionOptions(base, 5, 'test-ca').ssl).toMatchObject({
      ca: 'test-ca',
      rejectUnauthorized: true,
    });
  });

  it.each([
    '?sslmode=disable',
    '?sslmode=prefer',
    '?sslmode=allow',
    '?sslmode=no-verify',
    '?sslmode=verify-ca',
    '?sslmode=require&sslmode=disable',
    '?sslmode=disable&sslmode=require',
    '?sslmode=require&sslmode=require',
    '?sslmode=require&SSLMode=disable',
    '?%73slmode=disable',
    '?ssl%6dode=require',
    '?sslmode=%72equire',
    '?sslmode=require%00',
    '?sslmode=require&channel_binding=require&channel_binding=require',
    '?channel_binding=disable',
    '?ssl=false',
    '?ssl=0',
    '?ssl=no-verify',
    '?uselibpqcompat=true',
    '?sslmode=require&uselibpqcompat=true',
    '?sslrootcert=/private/file',
    '?sslcert=/private/file',
    '?sslkey=/private/file',
    '?host=other.invalid',
    '?port=5433',
    '?user=other',
    '?password=other',
    '?options=-c+search_path=public',
    '?sslmode=%',
    '?sslmode=require#fragment',
  ])('rejects URL control %s before a driver can connect', (query) => {
    expect(() => postgresConnectionOptions(base + query, 20)).toThrow(
      'POSTGRES_CONNECTION_CONFIG_INVALID',
    );
  });

  it.each([
    '',
    'not-a-url',
    base.replace('postgresql:', 'https:'),
    base.replace('qa_user:', ':'),
    base.replace('qa%40password@', '@'),
    base.replace('/qa_database', '/'),
    base.replace('qa%40password', 'qa%0apassword'),
    base.replace('qa%40password', 'qa%broken'),
    base.replace('db.qa.invalid', '%2ftmp'),
    base + '\n',
  ])('never includes rejected input in an error', (input) => {
    let failure: unknown;
    try {
      postgresConnectionOptions(input, 20);
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).message).toBe(
      'POSTGRES_CONNECTION_CONFIG_INVALID',
    );
    expect(failure).not.toHaveProperty('cause');
  });

  it('does not accept an empty explicit CA', () => {
    expect(() => postgresConnectionOptions(base, 20, ' ')).toThrow(
      'POSTGRES_CONNECTION_CONFIG_INVALID',
    );
  });
});
