import { Inject, Injectable, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource } from '@nestjs/typeorm';
import { S3Client } from '@aws-sdk/client-s3';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { DataSource } from 'typeorm';
import { AccountDeletion1794100000000 } from '../../database/migrations/1794100000000-AccountDeletion';
import { AccountDeletionDataService } from './account-deletion-data.service';
import type { DeletionLedger } from './ledger/deletion-ledger';
import { FileDeletionLedger } from './ledger/file-deletion-ledger';
import { R2DeletionLedger } from './ledger/r2-deletion-ledger';

export const DELETION_R2_CLIENT_FACTORY = 'DELETION_R2_CLIENT_FACTORY';
type ClientFactory = (config: ConfigService) => S3Client;
const TABLES = ['accounts', 'requests', 'retention', 'notifications'].map(
  (name) => 'account_deletion_' + name,
);
const UUID = /^[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}$/i;

/** Prepares only this feature, using the application's existing DB/R2 access. */
@Injectable()
export class AccountDeletionActivationService {
  constructor(
    @InjectDataSource('adminConnection') private readonly source: DataSource,
    private readonly config: ConfigService,
    private readonly data: AccountDeletionDataService,
    @Optional()
    @Inject(DELETION_R2_CLIENT_FACTORY)
    private readonly clientFactory?: ClientFactory,
  ) {}

  async prepare(): Promise<DeletionLedger | null> {
    const flag = this.config.get<string>('ACCOUNT_DELETION_ENABLED');
    if (flag !== undefined && !['true', 'false'].includes(flag))
      throw new Error('ACCOUNT_DELETION_ACTIVATION_CONFIGURATION_INVALID');
    if (
      flag === 'true' &&
      this.config.get<string>('ACCOUNT_DELETION_LEDGER_DIR')
    )
      return this.fileLedger();
    const required = [
      'R2_ENDPOINT',
      'R2_ACCESS_KEY_ID',
      'R2_SECRET_ACCESS_KEY',
      'R2_BUCKET',
    ];
    const present = required.filter((name) => this.config.get<string>(name));
    // Legacy flags cannot bypass recovery of an R2 history after a DB restore.
    if (!present.length && flag !== 'true') return null;
    if (present.length !== required.length)
      throw new Error('ACCOUNT_DELETION_R2_CONFIGURATION_REQUIRED');
    const wrappingSecret = this.config.get<string>('JWT_SECRET') ?? '';
    if (wrappingSecret.length < 32)
      throw new Error('ACCOUNT_DELETION_WRAPPING_CONFIGURATION_REQUIRED');
    let database: string;
    let backupRole: string;
    try {
      database = decodeURIComponent(
        new URL(
          this.config.getOrThrow<string>('DATABASE_URL_ADMIN'),
        ).pathname.slice(1),
      );
      backupRole = decodeURIComponent(
        new URL(this.config.getOrThrow<string>('DATABASE_URL_BACKUP')).username,
      );
      if (!database || !/^[a-z_][a-z\d_-]{0,62}$/i.test(backupRole))
        throw new Error();
    } catch {
      throw new Error('ACCOUNT_DELETION_DATABASE_CONFIGURATION_REQUIRED');
    }
    const prefix =
      '_account-deletion/v1/' +
      createHash('sha256')
        .update('sportcenter-account-deletion\0' + database)
        .digest('hex') +
      '/';
    const client =
      this.clientFactory?.(this.config) ??
      new S3Client({
        region: 'auto',
        endpoint: this.config.getOrThrow<string>('R2_ENDPOINT'),
        credentials: {
          accessKeyId: this.config.getOrThrow<string>('R2_ACCESS_KEY_ID'),
          secretAccessKey: this.config.getOrThrow<string>(
            'R2_SECRET_ACCESS_KEY',
          ),
        },
        maxAttempts: 3,
        requestHandler: { connectionTimeout: 10_000, requestTimeout: 30_000 },
      });
    // Never treat a failed deployment or unreadable history as a fresh install.
    const opened = await this.source.transaction(async (manager) => {
      await manager.query("SET LOCAL lock_timeout='20s'");
      await manager.query('SELECT pg_advisory_xact_lock(193590,0)');
      await this.data.inventory(manager);
      const relations = await manager.query<{ name: string }[]>(
        "SELECT tablename AS name FROM pg_tables WHERE schemaname='core' AND (tablename=ANY($1) OR tablename='account_deletion_installation')",
        [TABLES],
      );
      const installed = relations.some(
        (row) => row.name === 'account_deletion_installation',
      );
      const count = relations.filter((row) => TABLES.includes(row.name)).length;
      if ((count !== 0 && count !== 4) || (installed && count !== 4))
        throw new Error('ACCOUNT_DELETION_PARTIAL_SCHEMA');
      if (count === 4 && !installed)
        throw new Error('ACCOUNT_DELETION_UNVERIFIED_SCHEMA');
      let expectedLedgerId: string | undefined;
      if (installed) {
        const versions = await manager.query<
          { version: number; ledger_id: string }[]
        >(
          'SELECT version,ledger_id FROM core.account_deletion_installation WHERE singleton=true',
        );
        if (
          versions.length !== 1 ||
          versions[0].version !== 1 ||
          !UUID.test(versions[0].ledger_id)
        )
          throw new Error('ACCOUNT_DELETION_INSTALLATION_INVALID');
        expectedLedgerId = versions[0].ledger_id;
      }
      const requests =
        count === 4
          ? await manager.query<{ present: boolean }[]>(
              'SELECT EXISTS(SELECT 1 FROM core.account_deletion_requests) AS present',
            )
          : [{ present: false }];
      // Existing file-ledger history must never be silently moved into a new R2 history.
      if (requests[0].present && !installed)
        throw new Error('ACCOUNT_DELETION_EXISTING_HISTORY_REQUIRES_MIGRATION');
      const result = await R2DeletionLedger.open({
        client,
        bucket: this.config.getOrThrow<string>('R2_BUCKET'),
        prefix,
        wrappingSecret,
        databaseHasHistory: installed || requests[0].present,
        expectedLedgerId,
      });
      if (!count) {
        await new AccountDeletion1794100000000(backupRole).up(
          manager.queryRunner!,
        );
      }
      if (!installed) {
        await manager.query(`CREATE TABLE core.account_deletion_installation (
          singleton boolean PRIMARY KEY CHECK(singleton), version integer NOT NULL CHECK(version=1), ledger_id uuid NOT NULL);
          REVOKE ALL ON core.account_deletion_installation FROM PUBLIC;
          DO $acl$ DECLARE target record; BEGIN
            FOR target IN SELECT rolname FROM pg_roles WHERE rolname<>current_user AND NOT rolsuper LOOP
              EXECUTE format('REVOKE ALL ON core.account_deletion_installation FROM %I',target.rolname);
            END LOOP;
          END $acl$;`);
        await manager.query(
          'INSERT INTO core.account_deletion_installation VALUES(true,1,$1)',
          [result.ledgerId],
        );
        await manager.query(
          `GRANT SELECT ON core.account_deletion_installation TO "${backupRole}"`,
        );
      }
      await this.data.inventory(manager);
      return result;
    });
    for (const [key, value] of Object.entries({
      ACCOUNT_DELETION_SECRET: opened.operationSecret,
      ACCOUNT_DELETION_LEDGER_SECRET: opened.ledgerSecret,
      ACCOUNT_DELETION_ENABLED: 'true',
    }))
      this.config.set(key, value);
    return opened.ledger;
  }

  private fileLedger(): DeletionLedger {
    const key = this.config.get<string>('ACCOUNT_DELETION_LEDGER_SECRET') ?? '';
    if (
      !/^[a-f\d]{64}$/i.test(key) ||
      ['JWT_SECRET', 'JWT_REFRESH_SECRET', 'ACCOUNT_DELETION_SECRET'].some(
        (name) =>
          key.toLowerCase() === this.config.get<string>(name)?.toLowerCase(),
      )
    )
      throw new Error('ACCOUNT_DELETION_LEDGER_KEY_REQUIRED');
    return new FileDeletionLedger({
      directory: this.config.getOrThrow<string>('ACCOUNT_DELETION_LEDGER_DIR'),
      repositoryRoot: resolve(__dirname, '../../..'),
      hmacKey: Buffer.from(key, 'hex'),
    });
  }
}
