/* eslint-disable */
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { SchedulerRegistry } from '@nestjs/schedule';
import { CronJob } from 'cron';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';
import { ConfigService } from '@nestjs/config';
import { Repository } from 'typeorm';
import { R2StorageService } from './r2-storage.service';
import { CreateScheduleDto } from '../dto/create-schedule.dto';
import { CreateRetentionPolicyDto } from '../dto/create-retention-policy.dto';
import { BackupScheduleEntity } from '../entities/backup-schedule.entity';
import { BackupRetentionPolicyEntity } from '../entities/backup-retention-policy.entity';
import {
  buildScheduleConfig,
  describeSchedule,
  getNextExecutionFromJob,
  getUiScheduleType,
  normalizeTime,
} from '../utils/schedule.utils';

const execAsync = promisify(exec);

type BackupType = 'full' | 'critical';

export interface BackupSchedule {
  id: number;
  name: string;
  type: BackupType;
  scheduleType: 'daily' | 'weekly' | 'datetime';
  dayOfWeek: number | null;
  time: string | null;
  runAt: string | null;
  retentionDays: number;
  isActive: boolean;
  nextRunAt: string | null;
  lastRunAt: string | null;
  description: string;
  createdAt: string;
}

export interface BackupRetentionPolicy {
  id: number;
  name: string;
  type: 'all' | BackupType;
  scheduleType: 'daily' | 'weekly' | 'datetime';
  dayOfWeek: number | null;
  time: string | null;
  runAt: string | null;
  retentionDays: number;
  isActive: boolean;
  nextRunAt: string | null;
  lastRunAt: string | null;
  description: string;
  createdAt: string;
}

@Injectable()
export class DbBackupService implements OnModuleInit {
  private readonly logger = new Logger(DbBackupService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly schedulerRegistry: SchedulerRegistry,
    private readonly storage: R2StorageService,
    @InjectRepository(BackupScheduleEntity, 'adminConnection')
    private readonly scheduleRepository: Repository<BackupScheduleEntity>,
    @InjectRepository(BackupRetentionPolicyEntity, 'adminConnection')
    private readonly retentionRepository: Repository<BackupRetentionPolicyEntity>,
  ) {}

  async onModuleInit() {
    await this.registerPersistedSchedules();
    await this.registerPersistedRetentionPolicies();
  }

  private async registerPersistedSchedules() {
    const schedules = await this.scheduleRepository.find({
      where: { activo: true },
      order: { creado_en: 'ASC' },
    });

    for (const schedule of schedules) {
      await this.registerBackupSchedule(schedule);
    }
  }

  private async registerPersistedRetentionPolicies() {
    const policies = await this.retentionRepository.find({
      where: { activo: true },
      order: { creado_en: 'ASC' },
    });

    for (const policy of policies) {
      await this.registerRetentionPolicy(policy);
    }
  }

  private getFormattedDate(): string {
    const d = new Date();
    return `${d.getFullYear()}-${(d.getMonth() + 1).toString().padStart(2, '0')}-${d
      .getDate()
      .toString()
      .padStart(2, '0')}_${d.getHours().toString().padStart(2, '0')}-${d
      .getMinutes()
      .toString()
      .padStart(2, '0')}-${d.getSeconds().toString().padStart(2, '0')}`;
  }

  private getDbUrl() {
    return this.configService.get('DATABASE_URL_BACKUP');
  }

  private buildBackupPrefix(type: BackupType, folderName: string) {
    return `${type}/${folderName}`;
  }

  private getCriticalTables() {
    return [
      'core.users',
      'core.orders',
      'core.order_items',
      'core.pagos',
      'core.inventory',
      'core.inventory_movements',
      'core.products',
      'core.product_variants',
      'core.user_sessions',
    ];
  }

  private async executePgDump(type: BackupType, dumpPath: string) {
    const dbUrl = this.getDbUrl();
    const tableFlags =
      type === 'critical'
        ? this.getCriticalTables()
            .map((table) => `-t ${table}`)
            .join(' ')
        : '';

    const command = `pg_dump -Fc ${tableFlags} "${dbUrl}" -f "${dumpPath}"`;
    return execAsync(command);
  }

  private backupScheduleJobName(id: number) {
    return `backup_schedule_${id}`;
  }

  private retentionJobName(id: number) {
    return `backup_retention_${id}`;
  }

  private toBackupScheduleView(entity: BackupScheduleEntity): BackupSchedule {
    return {
      id: entity.id_backup_schedule,
      name: entity.nombre,
      type: entity.tipo_backup,
      scheduleType: getUiScheduleType(entity.modo_programacion),
      dayOfWeek: entity.dia_semana,
      time: normalizeTime(entity.hora),
      runAt: entity.fecha_ejecucion ? entity.fecha_ejecucion.toISOString() : null,
      retentionDays: entity.retencion_dias,
      isActive: entity.activo,
      nextRunAt: entity.proxima_ejecucion
        ? entity.proxima_ejecucion.toISOString()
        : null,
      lastRunAt: entity.ultima_ejecucion ? entity.ultima_ejecucion.toISOString() : null,
      description: describeSchedule(entity),
      createdAt: entity.creado_en.toISOString(),
    };
  }

  private toRetentionPolicyView(
    entity: BackupRetentionPolicyEntity,
  ): BackupRetentionPolicy {
    return {
      id: entity.id_retention_policy,
      name: entity.nombre,
      type: (entity.tipo_backup ?? 'all') as 'all' | BackupType,
      scheduleType: getUiScheduleType(entity.modo_programacion),
      dayOfWeek: entity.dia_semana,
      time: normalizeTime(entity.hora),
      runAt: entity.fecha_ejecucion ? entity.fecha_ejecucion.toISOString() : null,
      retentionDays: entity.retencion_dias,
      isActive: entity.activo,
      nextRunAt: entity.proxima_ejecucion
        ? entity.proxima_ejecucion.toISOString()
        : null,
      lastRunAt: entity.ultima_ejecucion ? entity.ultima_ejecucion.toISOString() : null,
      description: describeSchedule(entity),
      createdAt: entity.creado_en.toISOString(),
    };
  }

  private async updateBackupNextExecution(
    scheduleId: number,
    nextRunAt: Date | null,
    active?: boolean,
  ) {
    const update: Partial<BackupScheduleEntity> = {
      proxima_ejecucion: nextRunAt,
      actualizado_en: new Date(),
    };
    if (typeof active === 'boolean') {
      update.activo = active;
    }
    await this.scheduleRepository.update(scheduleId, update);
  }

  private async updateRetentionNextExecution(
    policyId: number,
    nextRunAt: Date | null,
    active?: boolean,
  ) {
    const update: Partial<BackupRetentionPolicyEntity> = {
      proxima_ejecucion: nextRunAt,
      actualizado_en: new Date(),
    };
    if (typeof active === 'boolean') {
      update.activo = active;
    }
    await this.retentionRepository.update(policyId, update);
  }

  private async markBackupScheduleExecuted(
    schedule: BackupScheduleEntity,
    nextRunAt: Date | null,
  ) {
    const isOneTime = schedule.modo_programacion === 'datetime';
    await this.scheduleRepository.update(schedule.id_backup_schedule, {
      ultima_ejecucion: new Date(),
      proxima_ejecucion: isOneTime ? null : nextRunAt,
      activo: isOneTime ? false : schedule.activo,
      actualizado_en: new Date(),
    });
  }

  private async markRetentionPolicyExecuted(
    policy: BackupRetentionPolicyEntity,
    nextRunAt: Date | null,
  ) {
    const isOneTime = policy.modo_programacion === 'datetime';
    await this.retentionRepository.update(policy.id_retention_policy, {
      ultima_ejecucion: new Date(),
      proxima_ejecucion: isOneTime ? null : nextRunAt,
      activo: isOneTime ? false : policy.activo,
      actualizado_en: new Date(),
    });
  }

  private createCronJob(
    mode: 'cron' | 'weekly' | 'datetime',
    cronExpression: string | null,
    runAt: Date | null,
    onTick: () => Promise<void>,
  ) {
    if (mode === 'datetime') {
      return new CronJob(runAt as Date, async () => {
        await onTick();
      });
    }

    return new CronJob(cronExpression as string, async () => {
      await onTick();
    });
  }

  private async registerBackupSchedule(schedule: BackupScheduleEntity) {
    const jobName = this.backupScheduleJobName(schedule.id_backup_schedule);
    if (this.schedulerRegistry.doesExist('cron', jobName)) {
      this.schedulerRegistry.deleteCronJob(jobName);
    }

    if (!schedule.activo) {
      return;
    }

    if (
      schedule.modo_programacion === 'datetime' &&
      schedule.fecha_ejecucion &&
      schedule.fecha_ejecucion.getTime() <= Date.now()
    ) {
      await this.updateBackupNextExecution(schedule.id_backup_schedule, null, false);
      return;
    }

    const job = this.createCronJob(
      schedule.modo_programacion,
      schedule.cron_expression,
      schedule.fecha_ejecucion,
      async () => {
        await this.createBackup(schedule.tipo_backup, 'scheduled', schedule.nombre);
        const nextRunAt = getNextExecutionFromJob(job);
        await this.markBackupScheduleExecuted(schedule, nextRunAt);
        if (schedule.modo_programacion === 'datetime') {
          this.schedulerRegistry.deleteCronJob(jobName);
          job.stop();
        }
      },
    );

    this.schedulerRegistry.addCronJob(jobName, job);
    job.start();
    await this.updateBackupNextExecution(
      schedule.id_backup_schedule,
      getNextExecutionFromJob(job),
    );
  }

  private async registerRetentionPolicy(policy: BackupRetentionPolicyEntity) {
    const jobName = this.retentionJobName(policy.id_retention_policy);
    if (this.schedulerRegistry.doesExist('cron', jobName)) {
      this.schedulerRegistry.deleteCronJob(jobName);
    }

    if (!policy.activo) {
      return;
    }

    if (
      policy.modo_programacion === 'datetime' &&
      policy.fecha_ejecucion &&
      policy.fecha_ejecucion.getTime() <= Date.now()
    ) {
      await this.updateRetentionNextExecution(policy.id_retention_policy, null, false);
      return;
    }

    const job = this.createCronJob(
      policy.modo_programacion,
      policy.cron_expression,
      policy.fecha_ejecucion,
      async () => {
        await this.cleanupOldBackups(
          policy.retencion_dias,
          (policy.tipo_backup ?? undefined) as BackupType | undefined,
        );
        const nextRunAt = getNextExecutionFromJob(job);
        await this.markRetentionPolicyExecuted(policy, nextRunAt);
        if (policy.modo_programacion === 'datetime') {
          this.schedulerRegistry.deleteCronJob(jobName);
          job.stop();
        }
      },
    );

    this.schedulerRegistry.addCronJob(jobName, job);
    job.start();
    await this.updateRetentionNextExecution(
      policy.id_retention_policy,
      getNextExecutionFromJob(job),
    );
  }

  async createBackup(
    type: BackupType,
    source: 'manual' | 'scheduled' = 'manual',
    scheduleName?: string,
  ) {
    const formattedDate = this.getFormattedDate();
    const folderName = `backup-${formattedDate}`;
    const prefix = this.buildBackupPrefix(type, folderName);
    const dumpFileName = `${type === 'full' ? 'full' : 'critical'}_${formattedDate}.dump`;
    const logFileName = `${type === 'full' ? 'full' : 'critical'}_${formattedDate}.log`;
    const tempDumpPath = path.join(process.cwd(), `${type}_${formattedDate}.dump`);

    try {
      const startedAt = new Date();
      this.logger.log(`Creating ${type} backup (${source})`);
      const result = await this.executePgDump(type, tempDumpPath);
      const file = await fs.readFile(tempDumpPath);
      const fileSize = file.byteLength;

      await this.storage.uploadBuffer(`${prefix}/${dumpFileName}`, file);

      const completedAt = new Date();
      const durationSeconds = (
        (completedAt.getTime() - startedAt.getTime()) /
        1000
      ).toFixed(2);
      const logContent = [
        `Tarea: Backup ${type === 'full' ? 'completo' : 'critico'}`,
        `Origen: ${source === 'manual' ? 'manual' : 'programado'}`,
        `Programacion: ${scheduleName ?? 'N/A'}`,
        `Inicio: ${startedAt.toISOString()}`,
        `Fin: ${completedAt.toISOString()}`,
        `Estado: SUCCESS`,
        '',
        'Resumen:',
        `- Tipo de backup: ${type === 'full' ? 'Completo' : 'Critico'}`,
        `- Archivo generado: ${dumpFileName}`,
        `- Tamano del dump: ${this.formatBytes(fileSize)}`,
        `- Carpeta destino: ${prefix}`,
        `- Duracion total: ${durationSeconds}s`,
        `- Subida a Cloudflare R2: completada`,
        `- Log generado: ${logFileName}`,
        ...(result.stdout?.trim()
          ? ['', `- Salida del comando: ${result.stdout.trim()}`]
          : []),
        ...(result.stderr?.trim()
          ? ['', `- Advertencias del comando: ${result.stderr.trim()}`]
          : []),
      ].join('\n');

      await this.storage.uploadText(`${prefix}/${logFileName}`, logContent);
      await fs.unlink(tempDumpPath);

      return {
        success: true,
        folder: prefix,
        dumpFile: dumpFileName,
        logFile: logFileName,
        source,
      };
    } catch (error: any) {
      const logContent = [
        `Tarea: Backup ${type === 'full' ? 'completo' : 'critico'}`,
        `Origen: ${source === 'manual' ? 'manual' : 'programado'}`,
        `Programacion: ${scheduleName ?? 'N/A'}`,
        `Estado: ERROR`,
        '',
        `Motivo: ${error?.message || 'Error desconocido'}`,
        ...(error?.stderr?.trim() ? ['', `Detalle tecnico: ${error.stderr.trim()}`] : []),
      ].join('\n');

      await this.storage.uploadText(`${prefix}/${logFileName}`, logContent);
      try {
        await fs.unlink(tempDumpPath);
      } catch {}

      this.logger.error(error);
      return { success: false, error: error?.message || 'Backup failed' };
    }
  }

  async createFullBackup() {
    return this.createBackup('full', 'manual');
  }

  async createCriticalTablesBackup() {
    return this.createBackup('critical', 'manual');
  }

  async listBackups() {
    const objects = await this.storage.list();
    const groups = new Map<string, any>();

    for (const object of objects) {
      const key = object.Key;
      if (!key) continue;
      const parts = key.split('/');
      if (parts.length < 3) continue;
      const [type, folder, fileName] = parts;
      if (!['full', 'critical'].includes(type)) continue;
      const groupKey = `${type}/${folder}`;

      if (!groups.has(groupKey)) {
        groups.set(groupKey, {
          key: groupKey,
          type,
          folder,
          dumpKey: null,
          dumpFileName: null,
          dumpSize: 0,
          logKey: null,
          logFileName: null,
          lastModified: object.LastModified,
        });
      }

      const group = groups.get(groupKey);
      if (fileName.endsWith('.dump')) {
        group.dumpKey = key;
        group.dumpFileName = fileName;
        group.dumpSize = object.Size ?? 0;
      }

      if (fileName.endsWith('.log')) {
        group.logKey = key;
        group.logFileName = fileName;
      }

      if (
        !group.lastModified ||
        (object.LastModified && object.LastModified > group.lastModified)
      ) {
        group.lastModified = object.LastModified;
      }
    }

    return Array.from(groups.values()).sort(
      (a, b) =>
        new Date(b.lastModified ?? 0).getTime() -
        new Date(a.lastModified ?? 0).getTime(),
    );
  }

  async downloadBackup(key: string) {
    return this.storage.downloadStream(key);
  }

  async getBackupLog(key: string) {
    return {
      key,
      content: await this.storage.downloadText(key),
    };
  }

  async deleteBackup(folderKey: string) {
    const objects = await this.storage.list(folderKey);
    await Promise.all(
      objects
        .map((object) => object.Key)
        .filter((key): key is string => !!key)
        .map((key) => this.storage.delete(key)),
    );

    return { success: true };
  }

  private formatBytes(bytes: number) {
    if (!bytes || bytes < 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let value = bytes;
    let unitIndex = 0;

    while (value >= 1024 && unitIndex < units.length - 1) {
      value /= 1024;
      unitIndex += 1;
    }

    return `${value.toFixed(value >= 10 || unitIndex === 0 ? 0 : 2)} ${units[unitIndex]}`;
  }

  async cleanupOldBackups(days = 30, type?: BackupType) {
    const objects = await this.storage.list();
    const now = Date.now();
    const maxAge = days * 24 * 60 * 60 * 1000;
    let deletedCount = 0;

    for (const object of objects) {
      if (!object.Key || !object.LastModified) continue;
      const [folderType] = object.Key.split('/');
      if (!['full', 'critical'].includes(folderType)) continue;
      if (type && folderType !== type) continue;

      const age = now - object.LastModified.getTime();
      if (age > maxAge) {
        await this.storage.delete(object.Key);
        deletedCount += 1;
      }
    }

    return { success: true, deletedOlderThanDays: days, deletedCount, type: type ?? 'all' };
  }

  async createSchedule(dto: CreateScheduleDto) {
    const type = dto.type === 'critical' ? 'critical' : 'full';
    const config = buildScheduleConfig(dto);

    const entity = this.scheduleRepository.create({
      nombre: dto.name,
      tipo_backup: type,
      ...config,
      activo: true,
      carpeta_destino: 'backups',
      retencion_dias: dto.retentionDays ?? 7,
      creado_en: new Date(),
      actualizado_en: new Date(),
    });

    const saved = await this.scheduleRepository.save(entity);
    await this.registerBackupSchedule(saved);
    const fresh = await this.scheduleRepository.findOneByOrFail({
      id_backup_schedule: saved.id_backup_schedule,
    });
    return this.toBackupScheduleView(fresh);
  }

  async listSchedules() {
    const items = await this.scheduleRepository.find({
      order: { creado_en: 'DESC' },
    });
    return items.map((item) => this.toBackupScheduleView(item));
  }

  async deleteSchedule(name: string) {
    const entity = await this.scheduleRepository.findOneBy({ nombre: name });
    if (!entity) {
      return { success: true };
    }

    const jobName = this.backupScheduleJobName(entity.id_backup_schedule);
    if (this.schedulerRegistry.doesExist('cron', jobName)) {
      this.schedulerRegistry.deleteCronJob(jobName);
    }

    await this.scheduleRepository.delete(entity.id_backup_schedule);
    return { success: true };
  }

  async createRetentionPolicy(dto: CreateRetentionPolicyDto) {
    const config = buildScheduleConfig(dto);
    const entity = this.retentionRepository.create({
      nombre: dto.name,
      tipo_backup: dto.type === 'all' ? null : (dto.type ?? null),
      carpeta_base: 'backups',
      retencion_dias: dto.retentionDays,
      ...config,
      activo: true,
      creado_en: new Date(),
      actualizado_en: new Date(),
    });

    const saved = await this.retentionRepository.save(entity);
    await this.registerRetentionPolicy(saved);
    const fresh = await this.retentionRepository.findOneByOrFail({
      id_retention_policy: saved.id_retention_policy,
    });
    return this.toRetentionPolicyView(fresh);
  }

  async listRetentionPolicies() {
    const items = await this.retentionRepository.find({
      order: { creado_en: 'DESC' },
    });
    return items.map((item) => this.toRetentionPolicyView(item));
  }

  async deleteRetentionPolicy(name: string) {
    const entity = await this.retentionRepository.findOneBy({ nombre: name });
    if (!entity) {
      return { success: true };
    }

    const jobName = this.retentionJobName(entity.id_retention_policy);
    if (this.schedulerRegistry.doesExist('cron', jobName)) {
      this.schedulerRegistry.deleteCronJob(jobName);
    }

    await this.retentionRepository.delete(entity.id_retention_policy);
    return { success: true };
  }
}
