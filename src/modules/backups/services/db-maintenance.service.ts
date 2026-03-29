/* eslint-disable */
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { SchedulerRegistry } from '@nestjs/schedule';
import { CronJob } from 'cron';
import { exec } from 'child_process';
import { promisify } from 'util';
import { promises as fs } from 'fs';
import * as path from 'path';
import { DataSource, Repository } from 'typeorm';
import { R2StorageService } from './r2-storage.service';
import { CreateScheduleDto } from '../dto/create-schedule.dto';
import { VacuumScheduleEntity } from '../entities/vacuum-schedule.entity';
import {
  APP_TIME_ZONE,
  buildScheduleConfig,
  describeSchedule,
  getNextExecutionFromJob,
  getUiScheduleType,
  normalizeTime,
} from '../utils/schedule.utils';

const execAsync = promisify(exec);

export interface VacuumSchedule {
  id: number;
  name: string;
  scheduleType: 'daily' | 'weekly' | 'datetime';
  dayOfWeek: number | null;
  time: string | null;
  runAt: string | null;
  targetSchema: string;
  isActive: boolean;
  nextRunAt: string | null;
  lastRunAt: string | null;
  description: string;
  createdAt: string;
}

@Injectable()
export class DbMaintenanceService implements OnModuleInit {
  private readonly logger = new Logger(DbMaintenanceService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly schedulerRegistry: SchedulerRegistry,
    private readonly storage: R2StorageService,
    @InjectDataSource('adminConnection')
    private readonly adminDataSource: DataSource,
    @InjectRepository(VacuumScheduleEntity, 'adminConnection')
    private readonly vacuumScheduleRepository: Repository<VacuumScheduleEntity>,
  ) {}

  async onModuleInit() {
    const schedules = await this.vacuumScheduleRepository.find({
      where: { activo: true },
      order: { creado_en: 'ASC' },
    });

    for (const schedule of schedules) {
      await this.registerVacuumSchedule(schedule);
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

  private getAdminDbUrl() {
    return this.configService.get('DATABASE_URL_ADMIN');
  }

  private vacuumScheduleJobName(id: number) {
    return `vacuum_schedule_${id}`;
  }

  private toVacuumScheduleView(entity: VacuumScheduleEntity): VacuumSchedule {
    return {
      id: entity.id_vacuum_schedule,
      name: entity.nombre,
      scheduleType: getUiScheduleType(entity.modo_programacion),
      dayOfWeek: entity.dia_semana,
      time: normalizeTime(entity.hora),
      runAt: entity.fecha_ejecucion ? entity.fecha_ejecucion.toISOString() : null,
      targetSchema: entity.esquema_objetivo,
      isActive: entity.activo,
      nextRunAt: entity.proxima_ejecucion ? entity.proxima_ejecucion.toISOString() : null,
      lastRunAt: entity.ultima_ejecucion ? entity.ultima_ejecucion.toISOString() : null,
      description: describeSchedule(entity),
      createdAt: entity.creado_en.toISOString(),
    };
  }

  private async updateVacuumNextExecution(
    scheduleId: number,
    nextRunAt: Date | null,
    active?: boolean,
  ) {
    const update: Partial<VacuumScheduleEntity> = {
      proxima_ejecucion: nextRunAt,
      actualizado_en: new Date(),
    };
    if (typeof active === 'boolean') {
      update.activo = active;
    }
    await this.vacuumScheduleRepository.update(scheduleId, update);
  }

  private async markVacuumExecuted(
    schedule: VacuumScheduleEntity,
    nextRunAt: Date | null,
  ) {
    const isOneTime = schedule.modo_programacion === 'datetime';
    await this.vacuumScheduleRepository.update(schedule.id_vacuum_schedule, {
      ultima_ejecucion: new Date(),
      proxima_ejecucion: isOneTime ? null : nextRunAt,
      activo: isOneTime ? false : schedule.activo,
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

    return new CronJob(
      cronExpression as string,
      async () => {
        await onTick();
      },
      null,
      false,
      APP_TIME_ZONE,
    );
  }

  private async registerVacuumSchedule(schedule: VacuumScheduleEntity) {
    const jobName = this.vacuumScheduleJobName(schedule.id_vacuum_schedule);
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
      await this.updateVacuumNextExecution(schedule.id_vacuum_schedule, null, false);
      return;
    }

    const job = this.createCronJob(
      schedule.modo_programacion,
      schedule.cron_expression,
      schedule.fecha_ejecucion,
      async () => {
        await this.runVacuumAnalyze('scheduled', schedule.nombre);
        const nextRunAt = getNextExecutionFromJob(job);
        await this.markVacuumExecuted(schedule, nextRunAt);
        if (schedule.modo_programacion === 'datetime') {
          this.schedulerRegistry.deleteCronJob(jobName);
          job.stop();
        }
      },
    );

    this.schedulerRegistry.addCronJob(jobName, job);
    job.start();
    await this.updateVacuumNextExecution(
      schedule.id_vacuum_schedule,
      getNextExecutionFromJob(job),
    );
  }

  private async buildCoreVacuumScript(fileName: string) {
    const tables = await this.adminDataSource.query(
      `
        SELECT tablename
        FROM pg_tables
        WHERE schemaname = 'core'
        ORDER BY tablename
      `,
    );

    const statements = tables
      .map((table: { tablename: string }) => {
        const tableName = String(table.tablename).replace(/"/g, '""');
        return `VACUUM (VERBOSE, ANALYZE) core."${tableName}";`;
      })
      .join('\n');

    if (!statements) {
      throw new Error(
        'No se encontraron tablas del esquema core para ejecutar VACUUM ANALYZE',
      );
    }

    const tempScriptPath = path.join(process.cwd(), fileName);
    await fs.writeFile(tempScriptPath, `${statements}\n`, 'utf8');
    return tempScriptPath;
  }

  private buildVacuumSummary(stderr: string, startedAt: Date, completedAt: Date) {
    const lines = stderr.split(/\r?\n/);
    const tableStats = new Map<
      string,
      {
        schema: string;
        table: string;
        deadTuplesRemoved: number;
        indexCleanup: boolean;
        analyzed: boolean;
      }
    >();

    for (const line of lines) {
      const finishedMatch = line.match(
        /finished vacuuming "([^"]+)\.([^".]+)\.([^"]+)": index scans: (\d+)/i,
      );
      if (finishedMatch) {
        const [, , schema, table, indexScans] = finishedMatch;
        const key = `${schema}.${table}`;
        const current = tableStats.get(key) ?? {
          schema,
          table,
          deadTuplesRemoved: 0,
          indexCleanup: false,
          analyzed: false,
        };
        current.indexCleanup = Number(indexScans) > 0;
        tableStats.set(key, current);
        continue;
      }

      const tuplesMatch = line.match(/tuples:\s+(\d+)\s+removed,\s+(\d+)\s+remain/i);
      if (tuplesMatch) {
        const lastKey = Array.from(tableStats.keys()).at(-1);
        if (!lastKey) continue;
        const current = tableStats.get(lastKey);
        if (!current) continue;
        current.deadTuplesRemoved = Number(tuplesMatch[1]);
        tableStats.set(lastKey, current);
        continue;
      }

      const analyzeMatch = line.match(/INFO:\s+analyzing "([^".]+)\.([^"]+)"/i);
      if (analyzeMatch) {
        const [, schema, table] = analyzeMatch;
        const key = `${schema}.${table}`;
        const current = tableStats.get(key) ?? {
          schema,
          table,
          deadTuplesRemoved: 0,
          indexCleanup: false,
          analyzed: false,
        };
        current.analyzed = true;
        tableStats.set(key, current);
      }
    }

    const allTables = Array.from(tableStats.values()).filter(
      (entry) => entry.schema === 'core',
    );
    const cleanedTables = allTables.filter((entry) => entry.deadTuplesRemoved > 0);
    const indexTables = allTables.filter((entry) => entry.indexCleanup);
    const analyzedTables = allTables.filter((entry) => entry.analyzed);
    const untouchedTables = allTables.filter((entry) => entry.deadTuplesRemoved === 0);
    const totalDeadTuples = cleanedTables.reduce(
      (sum, entry) => sum + entry.deadTuplesRemoved,
      0,
    );
    const durationMs = completedAt.getTime() - startedAt.getTime();
    const durationSeconds = (durationMs / 1000).toFixed(2);

    const formatTableList = (
      entries: typeof allTables,
      formatter?: (entry: (typeof allTables)[number]) => string,
    ) =>
      entries.length
        ? entries
            .map((entry) =>
              formatter ? formatter(entry) : `${entry.schema}.${entry.table}`,
            )
            .join('\n')
        : '(none)';

    return [
      'Resumen:',
      `- Esquema procesado: core`,
      `- Tablas revisadas: ${allTables.length}`,
      `- Tablas analizadas: ${analyzedTables.length}`,
      `- Tablas con limpieza real: ${cleanedTables.length}`,
      `- Filas muertas liberadas: ${totalDeadTuples}`,
      `- Tablas con limpieza de indices: ${indexTables.length}`,
      `- Duracion total: ${durationSeconds}s`,
      '',
      'Tablas donde se liberaron filas muertas:',
      formatTableList(
        cleanedTables,
        (entry) =>
          `- ${entry.schema}.${entry.table}: ${entry.deadTuplesRemoved} filas muertas liberadas`,
      ),
      '',
      'Tablas donde tambien se limpiaron indices:',
      formatTableList(indexTables, (entry) => `- ${entry.schema}.${entry.table}`),
      '',
      'Tablas que solo actualizaron estadisticas:',
      untouchedTables.length
        ? `- ${untouchedTables
            .map((entry) => `${entry.schema}.${entry.table}`)
            .join(', ')}`
        : '(ninguna)',
    ].join('\n');
  }

  async runVacuumAnalyze(
    source: 'manual' | 'scheduled' = 'manual',
    scheduleName?: string,
  ) {
    const formattedDate = this.getFormattedDate();
    const folder = `logsVacum/vacuum-${formattedDate}`;
    const logFile = `vacuum-${formattedDate}.log`;
    const scriptFile = `vacuum-core-${formattedDate}.sql`;
    let scriptPath = '';

    try {
      const startedAt = new Date();
      scriptPath = await this.buildCoreVacuumScript(scriptFile);
      const command = `psql "${this.getAdminDbUrl()}" -f "${scriptPath}"`;
      const result = await execAsync(command, { maxBuffer: 10 * 1024 * 1024 });
      const completedAt = new Date();
      const summary = this.buildVacuumSummary(
        result.stderr || '',
        startedAt,
        completedAt,
      );

      const content = [
        `Tarea: VACUUM ANALYZE`,
        `Origen: ${source === 'manual' ? 'manual' : 'programado'}`,
        `Programacion: ${scheduleName ?? 'N/A'}`,
        `Inicio: ${startedAt.toISOString()}`,
        `Fin: ${completedAt.toISOString()}`,
        `Estado: SUCCESS`,
        '',
        summary,
      ].join('\n');

      await this.storage.uploadText(`${folder}/${logFile}`, content);
      await fs.unlink(scriptPath).catch(() => undefined);

      return {
        success: true,
        folder,
        logKey: `${folder}/${logFile}`,
        logFile,
      };
    } catch (error: any) {
      const content = [
        `Tarea: VACUUM ANALYZE`,
        `Origen: ${source === 'manual' ? 'manual' : 'programado'}`,
        `Programacion: ${scheduleName ?? 'N/A'}`,
        `Estado: ERROR`,
        '',
        `Motivo: ${error?.message || 'Error desconocido'}`,
      ].join('\n');

      await this.storage.uploadText(`${folder}/${logFile}`, content);
      if (scriptPath) {
        await fs.unlink(scriptPath).catch(() => undefined);
      }
      this.logger.error(error);
      return { success: false, error: error?.message || 'Vacuum failed' };
    }
  }

  async listVacuumLogs() {
    const objects = await this.storage.list('logsVacum/');
    return objects
      .filter((object) => object.Key?.endsWith('.log'))
      .map((object) => ({
        key: object.Key,
        folder: object.Key?.split('/').slice(0, 2).join('/'),
        fileName: object.Key?.split('/').pop(),
        lastModified: object.LastModified,
        size: object.Size,
      }))
      .sort(
        (a, b) =>
          new Date(b.lastModified ?? 0).getTime() -
          new Date(a.lastModified ?? 0).getTime(),
      );
  }

  async getVacuumLog(key: string) {
    return {
      key,
      content: await this.storage.downloadText(key),
    };
  }

  async createVacuumSchedule(dto: CreateScheduleDto) {
    const config = buildScheduleConfig(dto);
    const entity = this.vacuumScheduleRepository.create({
      nombre: dto.name,
      esquema_objetivo: 'core',
      ...config,
      activo: true,
      creado_en: new Date(),
      actualizado_en: new Date(),
    });

    const saved = await this.vacuumScheduleRepository.save(entity);
    await this.registerVacuumSchedule(saved);
    const fresh = await this.vacuumScheduleRepository.findOneByOrFail({
      id_vacuum_schedule: saved.id_vacuum_schedule,
    });
    return this.toVacuumScheduleView(fresh);
  }

  async listVacuumSchedules() {
    const schedules = await this.vacuumScheduleRepository.find({
      order: { creado_en: 'DESC' },
    });
    return schedules.map((schedule) => this.toVacuumScheduleView(schedule));
  }

  async deleteVacuumSchedule(name: string) {
    const entity = await this.vacuumScheduleRepository.findOneBy({ nombre: name });
    if (!entity) {
      return { success: true };
    }

    const jobName = this.vacuumScheduleJobName(entity.id_vacuum_schedule);
    if (this.schedulerRegistry.doesExist('cron', jobName)) {
      this.schedulerRegistry.deleteCronJob(jobName);
    }

    await this.vacuumScheduleRepository.delete(entity.id_vacuum_schedule);
    return { success: true };
  }
}
