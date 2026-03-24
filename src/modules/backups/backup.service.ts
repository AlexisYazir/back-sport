/* eslint-disable */
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Cron } from '@nestjs/schedule';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';
import { DataSource } from 'typeorm';
import { InjectDataSource } from '@nestjs/typeorm';
import {
  S3Client,
  PutObjectCommand,
  ListObjectsV2Command,
  GetObjectCommand,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';

const execAsync = promisify(exec);

@Injectable()
export class BackupService {
  private readonly logger = new Logger(BackupService.name);
  private readonly s3: S3Client;

  constructor(
    private readonly configService: ConfigService, 
    @InjectDataSource('adminConnection')
    private readonly dataSource: DataSource,
  ) {
    this.s3 = new S3Client({
      region: 'auto',
      endpoint: this.configService.get<string>('R2_ENDPOINT')!,
      credentials: {
        accessKeyId: this.configService.get<string>('R2_ACCESS_KEY_ID')!,
        secretAccessKey: this.configService.get<string>(
          'R2_SECRET_ACCESS_KEY',
        )!,
      },
    });
    
  }

  private getBucket() {
    return this.configService.get('R2_BUCKET');
  }

  private getFormattedDate(): string {
    const d = new Date();
    return `${d.getFullYear()}-${(d.getMonth() + 1).toString().padStart(2, '0')}-${d
      .getDate()
      .toString()
      .padStart(
        2,
        '0',
      )}_${d.getHours().toString().padStart(2, '0')}-${d.getMinutes().toString().padStart(2, '0')}`;
  }

  //! Crear backup completo
  async createBackup() {
    const dbUrl = this.configService.get('DATABASE_URL_BACKUP');
    const filename = `full/backup_${this.getFormattedDate()}.dump`;
    const tempPath = path.join(process.cwd(), filename.replace('/', '_'));

    try {
      this.logger.log('Creating full database backup');

      await execAsync(`pg_dump -Fc "${dbUrl}" -f "${tempPath}"`);

      const file = await fs.readFile(tempPath);

      await this.s3.send(
        new PutObjectCommand({
          Bucket: this.getBucket(),
          Key: filename,
          Body: file,
        }),
      );

      await fs.unlink(tempPath);

      return { success: true, file: filename };
    } catch (error) {
      this.logger.error(error);
      return { success: false, error: error.message };
    }
  }

  //! Crear backup de tablas criticas
  async createCriticalTablesBackup() {
    this.logger.log('Creating critical tables backup');
    const dbUrl = this.configService.get('DATABASE_URL_BACKUP');

    const tables = [
      'users',
      'orders',
      'order_items',
      'pagos',
      'inventory',
      'inventory_movements',
      'products',
      'product_variants',
    ];

    const filename = `critical/critical_${this.getFormattedDate()}.dump`;
    const tempPath = path.join(process.cwd(), filename.replace('/', '_'));

    try {
      const tableFlags = tables.map((t) => `-t ${t}`).join(' ');

      await execAsync(`pg_dump -Fc ${tableFlags} "${dbUrl}" -f "${tempPath}"`);

      const file = await fs.readFile(tempPath);

      await this.s3.send(
        new PutObjectCommand({
          Bucket: this.getBucket(),
          Key: filename,
          Body: file,
        }),
      );

      await fs.unlink(tempPath);

      return { success: true, file: filename };
    } catch (error) {
      this.logger.error(error);
      return { success: false, error: error.message };
    }
  }

  //! LIST BACKUPS
  async listBackups() {
    const res = await this.s3.send(
      new ListObjectsV2Command({
        Bucket: this.getBucket(),
      }),
    );

    return res.Contents?.map((obj) => ({
      name: obj.Key,
      size: obj.Size,
      lastModified: obj.LastModified,
    }));
  }

  //! DOWNLOAD BACKUP
  async downloadBackup(type: string, name: string) {
    const decodedName = decodeURIComponent(name);

    const key = `${type}/${decodedName}`;

    const result = await this.s3.send(
      new GetObjectCommand({
        Bucket: this.getBucket(),
        Key: key,
      }),
    );

    return result.Body;
  }
  //! DELETE BACKUP
  async deleteBackup(type: string, name: string) {
    const key = `${type}/${name}`;

    await this.s3.send(
      new DeleteObjectCommand({
        Bucket: this.getBucket(),
        Key: key,
      }),
    );

    return { success: true };
  }

  //! DAILY CRON
  @Cron('0 3 * * *')
  async scheduledDailyBackup() {
    this.logger.log('Running daily backup');

    await this.createBackup();
    await this.createCriticalTablesBackup();

    await this.cleanupOldBackups(7);
  }

  //! DELETE OLD BACKUPS
  async cleanupOldBackups(days = 7) {
    const res = await this.s3.send(
      new ListObjectsV2Command({
        Bucket: this.getBucket(),
      }),
    );

    const now = Date.now();
    const maxAge = days * 24 * 60 * 60 * 1000;

    for (const obj of res.Contents || []) {
      if (!obj.LastModified) continue;

      const age = now - obj.LastModified.getTime();

      if (age > maxAge) {
        this.logger.log(`[x] deleting old backup ${obj.Key}`);

        await this.s3.send(
          new DeleteObjectCommand({
            Bucket: this.getBucket(),
            Key: obj.Key,
          }),
        );
      }
    }
  }

  //* PARA SUPERVICION DE RENDIMIENTO

  async getActiveConnections() {
    const result = await this.dataSource.query(`
      SELECT
          pid,
          usename,
          datname,
          application_name,
          client_addr,
          state,
          query
        FROM pg_stat_activity
        WHERE datname = 'db_sportcenter'
        ORDER BY 
        state = 'active' DESC, pid;
    `);

    return result;
  }

  async getDetailedLocks() {
    const result = await this.dataSource.query(`
      SELECT 
      l.pid,
      a.usename,
      a.datname,
      l.locktype,
      l.relation::regclass AS tabla,
      l.mode,
      l.granted
    FROM pg_locks l
    LEFT JOIN pg_stat_activity a ON l.pid = a.pid
    WHERE a.datname = 'db_sportcenter'
    ORDER BY l.pid;
    `);
    return result;
  }
async getBlockingLocks() {
  return await this.dataSource.query(`
    SELECT
      blocked.pid AS blocked_pid,
      blocked.usename AS blocked_user,
      blocking.pid AS blocking_pid,
      blocking.usename AS blocking_user,
      blocked.query AS blocked_query,
      blocking.query AS blocking_query
    FROM pg_locks bl
    JOIN pg_stat_activity blocked ON blocked.pid = bl.pid
    JOIN pg_locks kl 
      ON kl.locktype = bl.locktype
      AND kl.database IS NOT DISTINCT FROM bl.database
      AND kl.relation IS NOT DISTINCT FROM bl.relation
      AND kl.page IS NOT DISTINCT FROM bl.page
      AND kl.tuple IS NOT DISTINCT FROM bl.tuple
      AND kl.pid != bl.pid
    JOIN pg_stat_activity blocking ON blocking.pid = kl.pid
    WHERE NOT bl.granted;
  `);
}
  async getLongRunningQueries() {
    const result = await this.dataSource.query(`
      SELECT
        pid,
        usename,
        query,
        state,
        NOW() - query_start AS duration
      FROM pg_stat_activity
      WHERE state != 'idle'
      AND query_start IS NOT NULL
      ORDER BY duration DESC;
    `);

    return result;
  }

  async explainOrdersWithUsers() {
    const result = await this.dataSource.query(`
      EXPLAIN ANALYZE
      SELECT o.id_orden, u.nombre, o.total
      FROM orders o
      JOIN users u ON o.id_usuario = u.id_usuario
      WHERE o.estado = 'pendiente';
    `);

    return result;
  }

  // ===========================================
// ESTADÍSTICAS DE TABLAS CORREGIDAS
// ===========================================

// 1. TABLAS MÁS CONSULTADAS
async getMostQueriedTables() {
  const result = await this.dataSource.query(`
    SELECT
      schemaname,
      relname as tablename,
      seq_scan as total_escaneos_secuenciales,
      seq_tup_read as filas_leidas_secuencial,
      idx_scan as total_escaneos_indice,
      idx_tup_fetch as filas_leidas_indice,
      n_tup_ins as inserts,
      n_tup_upd as updates,
      n_tup_del as deletes,
      n_live_tup as filas_vivas,
      n_dead_tup as filas_muertas,
      (seq_scan + idx_scan) as total_consultas,
      CASE 
        WHEN (seq_scan + idx_scan) > 0 
        THEN ROUND((idx_scan::numeric / (seq_scan + idx_scan) * 100), 2)
        ELSE 0 
      END as porcentaje_uso_indices
    FROM pg_stat_user_tables
    WHERE schemaname = 'core'
    ORDER BY total_consultas DESC
    LIMIT 10;
  `);
  return result;
}

// 2. PESO DE CADA TABLA
async getTableSizes() {
  const result = await this.dataSource.query(`
    SELECT
      schemaname,
      relname as tablename,
      pg_size_pretty(pg_total_relation_size(relid)) as total_size_humano,
      pg_total_relation_size(relid) as total_size_bytes,
      pg_size_pretty(pg_relation_size(relid)) as tabla_size_humano,
      pg_size_pretty(pg_indexes_size(relid)) as indices_size_humano,
      pg_indexes_size(relid) as indices_size_bytes,
      n_live_tup as filas_aproximadas
    FROM pg_stat_user_tables
    WHERE schemaname = 'core'
    ORDER BY total_size_bytes DESC;
  `);
  return result;
}

// 3. INFORMACIÓN DE ÍNDICES
async getIndexInfo() {
  const result = await this.dataSource.query(`
    SELECT
      i.schemaname,
      i.relname as tablename,
      i.indexrelname as indexname,
      pg_get_indexdef(i.indexrelid) as indexdef,
      pg_size_pretty(pg_relation_size(i.indexrelid)) as index_size_humano,
      pg_relation_size(i.indexrelid) as index_size_bytes,
      i.idx_scan as veces_usado,
      i.idx_tup_read as filas_leidas,
      i.idx_tup_fetch as filas_obtenidas
    FROM pg_stat_user_indexes i
    WHERE i.schemaname = 'core'
    ORDER BY i.idx_scan DESC, index_size_bytes DESC;
  `);
  return result;
}

// 4. ESTADÍSTICAS DE BLOQUEOS POR TABLA
async getTableLockStats() {
  const result = await this.dataSource.query(`
    SELECT
      relation::regclass AS tabla,
      mode,
      COUNT(*) as cantidad_locks,
      COUNT(CASE WHEN granted THEN 1 END) as concedidos,
      COUNT(CASE WHEN NOT granted THEN 1 END) as esperando
    FROM pg_locks
    WHERE locktype = 'relation'
      AND relation::regclass::text LIKE 'core.%'
    GROUP BY relation, mode
    ORDER BY tabla, cantidad_locks DESC;
  `);
  return result;
}

// 5. ESTADÍSTICAS DE ESCANEOS
async getTableScanStats() {
  const result = await this.dataSource.query(`
    SELECT
      schemaname,
      relname as tablename,
      seq_scan,
      idx_scan,
      (seq_scan + idx_scan) as total_accesos,
      CASE 
        WHEN (seq_scan + idx_scan) > 0 
        THEN ROUND((seq_scan::numeric / (seq_scan + idx_scan) * 100), 2)
        ELSE 0 
      END as porcentaje_escaneo_secuencial
    FROM pg_stat_user_tables
    WHERE schemaname = 'core'
      AND (seq_scan + idx_scan) > 0
    ORDER BY porcentaje_escaneo_secuencial DESC
    LIMIT 10;
  `);
  return result;
}
}
