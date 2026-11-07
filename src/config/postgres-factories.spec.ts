import { ConfigService } from '@nestjs/config';
import { AppModule } from '../app.module';

type Factory = {
  inject?: unknown[];
  useFactory?: (config: ConfigService) => Record<string, unknown>;
};

function databaseFactories(): Required<Pick<Factory, 'useFactory'>>[] {
  const imports: unknown = Reflect.getMetadata('imports', AppModule);
  const factories: Required<Pick<Factory, 'useFactory'>>[] = [];
  function visit(candidate: unknown) {
    if (!candidate || typeof candidate !== 'object') return;
    const module = candidate as { imports?: unknown[]; providers?: unknown[] };
    for (const provider of module.providers ?? []) {
      if (!provider || typeof provider !== 'object') continue;
      const factory = provider as Factory;
      if (factory.useFactory && factory.inject?.includes(ConfigService))
        factories.push({ useFactory: factory.useFactory });
    }
    module.imports?.forEach(visit);
  }
  if (Array.isArray(imports)) imports.forEach(visit);
  return factories;
}

describe('the four real AppModule PostgreSQL factories', () => {
  const roles = [
    ['EDITOR', 'editorConnection', 20],
    ['ADMIN', 'adminConnection', 5],
    ['READER', 'readerConnection', 30],
    ['BACKUP', 'backupConnection', 2],
  ] as const;
  const config = Object.fromEntries(
    roles.map(([role]) => [
      'DATABASE_URL_' + role,
      `postgresql://qa_${role.toLowerCase()}:synthetic-password@db.qa.invalid/qa_database?sslmode=require&channel_binding=require`,
    ]),
  );

  it('preserves roles and settings while verifying every TLS peer', () => {
    const factories = databaseFactories();
    expect(factories).toHaveLength(4);
    const options = factories.map(({ useFactory }) =>
      useFactory(new ConfigService({ ...config, DATABASE_SSL_CA: 'test-ca' })),
    );
    roles.forEach(([role, name, limit], index) => {
      expect(options[index]).toMatchObject({
        name,
        type: 'postgres',
        username: 'qa_' + role.toLowerCase(),
        autoLoadEntities: true,
        synchronize: false,
        ssl: { rejectUnauthorized: true, ca: 'test-ca' },
        extra: { connectionLimit: limit, enableChannelBinding: true },
      });
      expect(options[index]).not.toHaveProperty('url');
      expect(options[index]).not.toHaveProperty('schema');
      expect(options[index].extra).not.toHaveProperty('ssl');
    });
  });

  it('rejects a downgrade in each factory during configuration', () => {
    databaseFactories().forEach(({ useFactory }, index) => {
      const role = roles[index][0];
      expect(() =>
        useFactory(
          new ConfigService({
            ...config,
            ['DATABASE_URL_' + role]: config['DATABASE_URL_' + role].replace(
              'sslmode=require',
              'sslmode=disable',
            ),
          }),
        ),
      ).toThrow('POSTGRES_CONNECTION_CONFIG_INVALID');
    });
  });
});
