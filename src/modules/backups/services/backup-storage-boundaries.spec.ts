import { BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SchedulerRegistry } from '@nestjs/schedule';
import { Readable } from 'node:stream';
import type { DataSource, Repository } from 'typeorm';
import type { BackupScheduleEntity } from '../entities/backup-schedule.entity';
import type { BackupRetentionPolicyEntity } from '../entities/backup-retention-policy.entity';
import type { VacuumScheduleEntity } from '../entities/vacuum-schedule.entity';
import { DbBackupService } from './db-backup.service';
import { DbMaintenanceService } from './db-maintenance.service';
import type { R2StorageService } from './r2-storage.service';

describe('Backup and maintenance API storage boundaries', () => {
  let storage: jest.Mocked<
    Pick<
      R2StorageService,
      'list' | 'downloadStream' | 'downloadText' | 'delete'
    >
  >;
  let backups: DbBackupService;
  let maintenance: DbMaintenanceService;
  const folder = 'backup-2026-11-08_10-00-00';
  beforeEach(() => {
    storage = {
      list: jest.fn().mockResolvedValue([]),
      downloadStream: jest.fn(),
      downloadText: jest.fn().mockResolvedValue('synthetic log'),
      delete: jest.fn().mockResolvedValue(undefined),
    };
    const config = new ConfigService();
    const scheduler = new SchedulerRegistry();
    backups = new DbBackupService(
      config,
      scheduler,
      storage as unknown as R2StorageService,
      {} as Repository<BackupScheduleEntity>,
      {} as Repository<BackupRetentionPolicyEntity>,
    );
    maintenance = new DbMaintenanceService(
      config,
      scheduler,
      storage as unknown as R2StorageService,
      {} as DataSource,
      {} as Repository<VacuumScheduleEntity>,
    );
  });

  it.each(['full', 'critical'])(
    'preserves download/log contracts for %s backups',
    async (type) => {
      const dump = `${type}/${folder}/${type}_2026-11-08_10-00-00.dump`;
      const log = dump.replace('.dump', '.log');
      const stream = Readable.from(['synthetic']);
      storage.downloadStream.mockResolvedValue(
        stream as Awaited<ReturnType<R2StorageService['downloadStream']>>,
      );
      await expect(backups.downloadBackup(dump)).resolves.toBe(stream);
      await expect(backups.getBackupLog(log)).resolves.toEqual({
        key: log,
        content: 'synthetic log',
      });
      expect(storage.downloadStream).toHaveBeenCalledWith(dump);
      expect(storage.downloadText).toHaveBeenCalledWith(log);
    },
  );

  it.each([
    '',
    'private/journal/head.log',
    'account-deletion/head.json',
    'logs/2026-11-08/users.log',
    'logsVacum/vacuum-date/vacuum.log',
    'full/folder/../head.dump',
    'full/../head.dump',
    'full/folder%2Fjournal/head.dump',
    'full/folder/head.dump\r\n',
  ])('rejects inaccessible keys in both backup readers: %j', async (key) => {
    await expect(backups.downloadBackup(key)).rejects.toBeInstanceOf(
      BadRequestException,
    );
    await expect(backups.getBackupLog(key)).rejects.toBeInstanceOf(
      BadRequestException,
    );
    expect(storage.downloadStream).not.toHaveBeenCalled();
    expect(storage.downloadText).not.toHaveBeenCalled();
  });

  it('never treats a log as a dump or a dump as a log', async () => {
    await expect(
      backups.downloadBackup('full/folder/file.log'),
    ).rejects.toThrow(BadRequestException);
    await expect(
      backups.getBackupLog('critical/folder/file.dump'),
    ).rejects.toThrow(BadRequestException);
    expect(storage.downloadStream).not.toHaveBeenCalled();
    expect(storage.downloadText).not.toHaveBeenCalled();
  });

  it.each([
    '',
    '/',
    'full',
    'full/',
    'critical/',
    'logs/folder',
    'private/journal',
    'full/..',
    'full/one/two',
    'full/%2E%2E',
    'full/folder\n',
    'full/folder\r\n',
  ])('rejects broad/deeper deletion prefixes: %j', async (key) => {
    await expect(backups.deleteBackup(key)).rejects.toBeInstanceOf(
      BadRequestException,
    );
    expect(storage.list).not.toHaveBeenCalled();
    expect(storage.delete).not.toHaveBeenCalled();
  });

  it('deletes only the exact selected folder, including its trailing delimiter', async () => {
    storage.list.mockResolvedValue([
      { Key: 'full/selected/data.dump' },
      { Key: 'full/selected/data.log' },
      { Key: 'full/selected-suffix/data.dump' },
      { Key: 'critical/selected/data.dump' },
      { Key: 'private/journal/head.json' },
      {},
    ]);
    await expect(backups.deleteBackup('full/selected')).resolves.toEqual({
      success: true,
    });
    expect(storage.list).toHaveBeenCalledWith('full/selected/');
    expect(storage.delete.mock.calls).toEqual([
      ['full/selected/data.dump'],
      ['full/selected/data.log'],
    ]);
  });

  it('lists only backup roots and preserves grouped view/sorting', async () => {
    const earlier = new Date('2026-11-01T00:00:00Z');
    const later = new Date('2026-11-02T00:00:00Z');
    storage.list.mockImplementation((prefix) =>
      Promise.resolve(
        prefix === 'full/'
          ? [
              {
                Key: `full/${folder}/full.dump`,
                Size: 123,
                LastModified: earlier,
              },
              { Key: `full/${folder}/full.log`, LastModified: earlier },
              { Key: 'private/journal/head.json', LastModified: later },
            ]
          : [{ Key: 'critical/new/critical.dump', LastModified: later }],
      ),
    );
    const groups = await backups.listBackups();
    expect(storage.list.mock.calls).toEqual([['full/'], ['critical/']]);
    expect(groups).toHaveLength(2);
    expect(groups[0]).toMatchObject({ key: 'critical/new', type: 'critical' });
    expect(groups[1]).toMatchObject({
      key: `full/${folder}`,
      dumpKey: `full/${folder}/full.dump`,
      dumpSize: 123,
      logKey: `full/${folder}/full.log`,
    });
  });

  it('retains normal backup cleanup while excluding every other namespace', async () => {
    const old = new Date('2000-01-01T00:00:00Z');
    storage.list.mockResolvedValue([
      { Key: 'full/old/file.dump', LastModified: old },
      { Key: 'critical/old/file.log', LastModified: old },
      { Key: 'private/journal/head.json', LastModified: old },
      { Key: 'logs/old/users.log', LastModified: old },
    ]);
    const result = await backups.cleanupOldBackups(30, 'full');
    expect(storage.list).toHaveBeenCalledWith('full/');
    expect(storage.delete).toHaveBeenCalledTimes(1);
    expect(storage.delete).toHaveBeenCalledWith('full/old/file.dump');
    expect(result.deletedOlderThanDays).toBe(30);
  });

  it('log retention never deletes a journal returned outside its requested prefix', async () => {
    const old = new Date('2000-01-01T00:00:00Z');
    storage.list.mockResolvedValue([
      { Key: 'logs/old/users.log', LastModified: old },
      { Key: 'private/journal/head.json', LastModified: old },
    ]);
    await backups.cleanupLogs(90);
    expect(storage.list).toHaveBeenCalledWith('logs/');
    expect(storage.delete.mock.calls).toEqual([['logs/old/users.log']]);
  });

  it('preserves vacuum logs while rejecting every other key in that reader', async () => {
    const key =
      'logsVacum/vacuum-2026-11-08_10-00-00/vacuum-2026-11-08_10-00-00.log';
    await expect(maintenance.getVacuumLog(key)).resolves.toEqual({
      key,
      content: 'synthetic log',
    });
    storage.downloadText.mockClear();
    for (const invalid of [
      'private/journal/head.log',
      'full/folder/full.log',
      'logsVacum/../head.log',
    ]) {
      await expect(maintenance.getVacuumLog(invalid)).rejects.toBeInstanceOf(
        BadRequestException,
      );
    }
    expect(storage.downloadText).not.toHaveBeenCalled();
  });
});
