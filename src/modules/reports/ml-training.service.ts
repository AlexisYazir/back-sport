import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Cron } from '@nestjs/schedule';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { spawn } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import { join, resolve } from 'path';
import { DataSource, Repository } from 'typeorm';
import { DataMiningReportsService } from './data-mining-reports.service';
import { RunMlTrainingDto } from './dto/run-ml-training.dto';
import { UpdateMlScheduleDto } from './dto/update-ml-schedule.dto';
import { MlModelRunEntity } from './entities/ml-model-run.entity';
import {
  MlPipeline,
  MlTrainingScheduleEntity,
} from './entities/ml-training-schedule.entity';

interface TrainingManifest {
  status: string;
  duration_ms: number;
  pipelines: Record<
    string,
    {
      rows: number;
      result_rows: number;
      metrics: Record<string, unknown>;
      files: string[];
    }
  >;
}

@Injectable()
export class MlTrainingService implements OnModuleInit {
  private readonly logger = new Logger(MlTrainingService.name);
  private readonly lockId = 2026072301;
  private readonly defaultPipelines: MlPipeline[] = [
    'demand',
    'recommendation',
    'clustering',
  ];

  constructor(
    @InjectDataSource('adminConnection')
    private readonly adminDataSource: DataSource,
    @InjectRepository(MlTrainingScheduleEntity, 'adminConnection')
    private readonly scheduleRepository: Repository<MlTrainingScheduleEntity>,
    @InjectRepository(MlModelRunEntity, 'adminConnection')
    private readonly runRepository: Repository<MlModelRunEntity>,
    private readonly configService: ConfigService,
    private readonly dataMiningReportsService: DataMiningReportsService,
  ) {}

  async onModuleInit(): Promise<void> {
    try {
      const schedules = await this.scheduleRepository.find({
        where: { activo: true },
      });
      for (const schedule of schedules) {
        if (!schedule.proxima_ejecucion) {
          await this.setNextExecution(schedule);
        }
      }
    } catch (error) {
      this.logger.warn(
        `La programación ML aún no está disponible: ${this.errorMessage(error)}`,
      );
    }
  }

  async listSchedules(): Promise<MlTrainingScheduleEntity[]> {
    return this.scheduleRepository.find({
      order: { fecha_creacion: 'ASC' },
    });
  }

  async listRuns(limit = 30): Promise<MlModelRunEntity[]> {
    return this.runRepository.find({
      order: { fecha_inicio: 'DESC' },
      take: Math.min(Math.max(limit, 1), 100),
    });
  }

  async updateSchedule(
    id: number,
    dto: UpdateMlScheduleDto,
    userId: number,
  ): Promise<MlTrainingScheduleEntity> {
    const schedule = await this.scheduleRepository.findOneBy({
      id_programacion: id,
    });
    if (!schedule) {
      throw new NotFoundException(
        'Programación de entrenamiento no encontrada',
      );
    }

    if (dto.nombre !== undefined) schedule.nombre = dto.nombre.trim();
    if (dto.diaMes !== undefined) schedule.dia_mes = dto.diaMes;
    if (dto.hora !== undefined) schedule.hora = `${dto.hora}:00`;
    if (dto.zonaHoraria !== undefined) {
      await this.validateTimezone(dto.zonaHoraria);
      schedule.zona_horaria = dto.zonaHoraria;
    }
    if (dto.pipelines !== undefined) schedule.pipelines = dto.pipelines;
    if (dto.activo !== undefined) schedule.activo = dto.activo;
    schedule.actualizado_por = userId;
    schedule.fecha_actualizacion = new Date();
    schedule.proxima_ejecucion = schedule.activo
      ? await this.calculateNextExecution(schedule)
      : null;

    return this.scheduleRepository.save(schedule);
  }

  async startManualRun(
    dto: RunMlTrainingDto,
    userId: number,
  ): Promise<{ message: string; runId: string }> {
    const pipelines = dto.pipelines ?? this.defaultPipelines;
    const run = await this.runRepository.save(
      this.runRepository.create({
        id_programacion: null,
        origen: 'manual',
        estado: 'queued',
        pipelines,
        fecha_inicio: new Date(),
        fecha_fin: null,
        duracion_ms: null,
        filas_dataset: null,
        metricas: null,
        artefactos: null,
        salida: null,
        error: null,
        ejecutado_por: userId,
      }),
    );

    void this.executeRun(run.id_ejecucion, pipelines);
    return {
      message: 'Entrenamiento agregado a la cola',
      runId: run.id_ejecucion,
    };
  }

  @Cron('0 * * * * *')
  async processDueSchedule(): Promise<void> {
    let schedule: MlTrainingScheduleEntity | null = null;
    try {
      const claimedResult = await this.adminDataSource.query(
        `
        WITH due AS (
          SELECT id_programacion
          FROM core.ml_training_schedules
          WHERE activo = true
            AND proxima_ejecucion IS NOT NULL
            AND proxima_ejecucion <= CURRENT_TIMESTAMP
          ORDER BY proxima_ejecucion ASC
          FOR UPDATE SKIP LOCKED
          LIMIT 1
        )
        UPDATE core.ml_training_schedules schedule
        SET proxima_ejecucion = CURRENT_TIMESTAMP + INTERVAL '6 hours',
            fecha_actualizacion = CURRENT_TIMESTAMP
        FROM due
        WHERE schedule.id_programacion = due.id_programacion
        RETURNING schedule.id_programacion;
        `,
      );
      const claimedRow = Array.isArray(claimedResult?.[0])
        ? claimedResult[0][0]
        : claimedResult?.[0];
      const scheduleId = Number(claimedRow?.id_programacion);
      if (!Number.isInteger(scheduleId) || scheduleId <= 0) return;

      schedule = await this.scheduleRepository.findOneBy({
        id_programacion: scheduleId,
      });
      if (!schedule) {
        throw new Error(
          `No se encontró la programación ML reclamada (${scheduleId})`,
        );
      }
      const pipelines = this.normalizePipelines(schedule.pipelines);

      const run = await this.runRepository.save(
        this.runRepository.create({
          id_programacion: schedule.id_programacion,
          origen: 'scheduled',
          estado: 'queued',
          pipelines,
          fecha_inicio: new Date(),
          fecha_fin: null,
          duracion_ms: null,
          filas_dataset: null,
          metricas: null,
          artefactos: null,
          salida: null,
          error: null,
          ejecutado_por: null,
        }),
      );
      await this.executeRun(run.id_ejecucion, pipelines);
    } catch (error) {
      this.logger.error(
        `No fue posible procesar la programación ML: ${this.errorMessage(error)}`,
      );
    } finally {
      if (schedule) {
        schedule.ultima_ejecucion = new Date();
        await this.setNextExecution(schedule).catch((error) =>
          this.logger.error(
            `No fue posible calcular la siguiente ejecución: ${this.errorMessage(error)}`,
          ),
        );
      }
    }
  }

  private async executeRun(
    runId: string,
    pipelines: MlPipeline[],
  ): Promise<void> {
    const queryRunner = this.adminDataSource.createQueryRunner();
    await queryRunner.connect();
    let acquired = false;
    const startedAt = Date.now();
    try {
      const lock = await queryRunner.query(
        'SELECT pg_try_advisory_lock($1) AS acquired;',
        [this.lockId],
      );
      acquired = Boolean(lock[0]?.acquired);
      if (!acquired) {
        await this.runRepository.update(runId, {
          estado: 'skipped',
          fecha_fin: new Date(),
          duracion_ms: Date.now() - startedAt,
          error: 'Ya existe otro entrenamiento en ejecución.',
        });
        return;
      }

      await this.runRepository.update(runId, {
        estado: 'running',
        fecha_inicio: new Date(startedAt),
      });

      const paths = this.resolvePaths();
      let exportOutput = '';
      if (this.configService.get('ML_REFRESH_DATASETS', 'true') !== 'false') {
        const connection = this.configService.get<string>(
          'DATABASE_URL_READER',
        );
        if (!connection) {
          throw new Error('DATABASE_URL_READER no está configurada');
        }
        exportOutput = await this.runCommand(
          this.configService.get('PSQL_PATH', 'psql'),
          [connection, '-v', 'ON_ERROR_STOP=1', '-f', paths.exportScript],
          paths.backendRoot,
        );
      }

      const pythonExecutable = this.configService.get(
        'ML_PYTHON_EXECUTABLE',
        process.platform === 'win32' ? 'py' : 'python3',
      );
      const trainingOutput = await this.runCommand(
        pythonExecutable,
        [
          paths.trainingScript,
          '--datasets-dir',
          paths.datasetsDir,
          '--output-dir',
          paths.outputDir,
          '--models-dir',
          paths.modelsDir,
          '--pipelines',
          pipelines.join(','),
        ],
        paths.backendRoot,
      );

      const manifest = JSON.parse(
        readFileSync(paths.manifestFile, 'utf8'),
      ) as TrainingManifest;
      const rows = Object.fromEntries(
        Object.entries(manifest.pipelines).map(([name, result]) => [
          name,
          result.rows,
        ]),
      );
      const metrics = Object.fromEntries(
        Object.entries(manifest.pipelines).map(([name, result]) => [
          name,
          result.metrics,
        ]),
      );
      const artifacts = Object.fromEntries(
        Object.entries(manifest.pipelines).map(([name, result]) => [
          name,
          result.files,
        ]),
      );

      this.dataMiningReportsService.clearCache();
      await this.runRepository.update(runId, {
        estado: 'succeeded',
        fecha_fin: new Date(),
        duracion_ms: Date.now() - startedAt,
        filas_dataset: rows,
        metricas: metrics,
        artefactos: artifacts,
        salida: this.limitOutput(`${exportOutput}\n${trainingOutput}`),
        error: null,
      });
      this.logger.log(`Entrenamiento ML ${runId} completado`);
    } catch (error) {
      const message = this.errorMessage(error);
      await this.runRepository.update(runId, {
        estado: 'failed',
        fecha_fin: new Date(),
        duracion_ms: Date.now() - startedAt,
        error: this.limitOutput(message),
      });
      this.logger.error(`Entrenamiento ML ${runId} falló: ${message}`);
    } finally {
      if (acquired) {
        await queryRunner
          .query('SELECT pg_advisory_unlock($1);', [this.lockId])
          .catch(() => undefined);
      }
      await queryRunner.release();
    }
  }

  private resolvePaths(): {
    backendRoot: string;
    exportScript: string;
    trainingScript: string;
    datasetsDir: string;
    outputDir: string;
    modelsDir: string;
    manifestFile: string;
  } {
    const candidates = [
      resolve(process.cwd()),
      resolve(process.cwd(), 'back-sport'),
      resolve(process.cwd(), '..', 'back-sport'),
    ];
    const backendRoot = candidates.find(
      (candidate) =>
        existsSync(join(candidate, 'package.json')) &&
        existsSync(join(candidate, 'ml', 'training', 'train_models.py')),
    );
    if (!backendRoot) {
      throw new Error('No se encontró la raíz del backend Sport Center');
    }

    const outputDir = join(backendRoot, 'data', 'data-mining');
    const datasetMode = this.configService
      .get('ML_DATASET_MODE', 'academic')
      .trim()
      .toLowerCase();
    if (!['academic', 'operational'].includes(datasetMode)) {
      throw new Error('ML_DATASET_MODE debe ser "academic" u "operational"');
    }
    const exportScript =
      datasetMode === 'operational'
        ? join(
            backendRoot,
            'ml',
            'training',
            '00_export_operational_datasets.sql',
          )
        : join(
            backendRoot,
            'ml',
            'training',
            '00_export_academic_datasets.sql',
          );
    return {
      backendRoot,
      exportScript,
      trainingScript: join(backendRoot, 'ml', 'training', 'train_models.py'),
      datasetsDir: outputDir,
      outputDir,
      modelsDir: join(backendRoot, 'ml', 'models'),
      manifestFile: join(outputDir, 'training-manifest.json'),
    };
  }

  private runCommand(
    executable: string,
    args: string[],
    cwd: string,
  ): Promise<string> {
    return new Promise((resolveCommand, rejectCommand) => {
      const child = spawn(executable, args, {
        cwd,
        env: process.env,
        shell: false,
        windowsHide: true,
      });
      let output = '';
      let errors = '';
      const timeout = setTimeout(
        () => {
          child.kill();
          rejectCommand(new Error('El entrenamiento excedió 30 minutos'));
        },
        30 * 60 * 1000,
      );

      child.stdout.on('data', (chunk) => {
        output += String(chunk);
      });
      child.stderr.on('data', (chunk) => {
        errors += String(chunk);
      });
      child.on('error', (error) => {
        clearTimeout(timeout);
        rejectCommand(error);
      });
      child.on('close', (code) => {
        clearTimeout(timeout);
        if (code === 0) {
          resolveCommand(this.limitOutput(output));
          return;
        }
        rejectCommand(
          new Error(
            this.limitOutput(
              `${executable} terminó con código ${code}. ${errors || output}`,
            ),
          ),
        );
      });
    });
  }

  private async setNextExecution(
    schedule: MlTrainingScheduleEntity,
  ): Promise<void> {
    const nextExecution = schedule.activo
      ? await this.calculateNextExecution(schedule)
      : null;
    await this.scheduleRepository.update(schedule.id_programacion, {
      ultima_ejecucion: schedule.ultima_ejecucion,
      proxima_ejecucion: nextExecution,
      fecha_actualizacion: new Date(),
    });
  }

  private async calculateNextExecution(
    schedule: Pick<
      MlTrainingScheduleEntity,
      'dia_mes' | 'hora' | 'zona_horaria'
    >,
  ): Promise<Date> {
    const [hour, minute] = schedule.hora.split(':').map(Number);
    const result = await this.adminDataSource.query(
      `
      WITH local_time AS (
        SELECT CURRENT_TIMESTAMP AT TIME ZONE $4 AS current_local
      ),
      candidate AS (
        SELECT
          current_local,
          date_trunc('month', current_local)
            + make_interval(days => $1 - 1, hours => $2, mins => $3)
            AS candidate_local
        FROM local_time
      )
      SELECT (
        CASE
          WHEN candidate_local > current_local THEN candidate_local
          ELSE candidate_local + INTERVAL '1 month'
        END
      ) AT TIME ZONE $4 AS next_execution
      FROM candidate;
      `,
      [schedule.dia_mes, hour, minute, schedule.zona_horaria],
    );
    return new Date(result[0].next_execution);
  }

  private async validateTimezone(timezone: string): Promise<void> {
    const result = await this.adminDataSource.query(
      'SELECT EXISTS (SELECT 1 FROM pg_timezone_names WHERE name = $1) AS valid;',
      [timezone],
    );
    if (!result[0]?.valid) {
      throw new BadRequestException('Zona horaria no válida');
    }
  }

  private normalizePipelines(value: unknown): MlPipeline[] {
    const allowed = new Set<MlPipeline>(this.defaultPipelines);
    let parsed = value;

    if (typeof parsed === 'string') {
      try {
        parsed = JSON.parse(parsed);
      } catch {
        parsed = [];
      }
    }

    const pipelines = Array.isArray(parsed)
      ? parsed.filter(
          (pipeline): pipeline is MlPipeline =>
            typeof pipeline === 'string' &&
            allowed.has(pipeline as MlPipeline),
        )
      : [];

    return pipelines.length > 0 ? [...new Set(pipelines)] : this.defaultPipelines;
  }

  private errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
  }

  private limitOutput(value: string): string {
    const clean = String(value || '').trim();
    return clean.length > 12000 ? clean.slice(-12000) : clean;
  }
}
