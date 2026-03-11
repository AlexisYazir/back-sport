/* eslint-disable */
import { Injectable, BadRequestException, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import * as fs from 'fs/promises';
import { Repository } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import { InventoryMovements } from '../products/entities/inventory/inventory_movements.entity';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import { Cron } from '@nestjs/schedule';

const execAsync = promisify(exec);

@Injectable()
export class BackupService {
  private readonly logger = new Logger(BackupService.name);
  private readonly backupPath = path.join(process.cwd(), 'backups');

  // Tablas críticas para backup diario
  private readonly criticalTables = [
    'users',
    'orders',
    'order_items',
    'pagos',
    'inventory_movements',
    'inventory',
    'products',
    'product_variants',
  ];

  constructor(
    @InjectRepository(InventoryMovements, 'readerConnection')
    private readonly inventoryMovementsRepository: Repository<InventoryMovements>,
    private readonly configService: ConfigService,
  ) {
    this.ensureBackupDirectory();
  }

  private async ensureBackupDirectory() {
    try {
      await fs.access(this.backupPath);
    } catch {
      await fs.mkdir(this.backupPath, { recursive: true });
    }
  }

  private getFormattedDate(): string {
    const date = new Date();
    const year = date.getFullYear();
    const month = (date.getMonth() + 1).toString().padStart(2, '0');
    const day = date.getDate().toString().padStart(2, '0');
    const hours = date.getHours().toString().padStart(2, '0');
    const minutes = date.getMinutes().toString().padStart(2, '0');
    return `${year}-${month}-${day}_${hours}-${minutes}`;
  }

  //! backup inventory_movements
  async backupInventoryMovements(): Promise<{ message: string; file: string }> {
    try {
      this.logger.log('Iniciando backup de inventory_movements...');

      const movements = await this.inventoryMovementsRepository.find({
        order: { fecha: 'DESC' },
      });

      if (movements.length === 0) {
        throw new BadRequestException('No hay movimientos para respaldar');
      }

      let sql = `-- Backup de inventory_movements\n`;
      sql += `-- Fecha: ${new Date().toLocaleString()}\n`;
      sql += `-- Total registros: ${movements.length}\n\n`;
      sql += `BEGIN;\n\n`;

      movements.forEach((m) => {
        sql += `INSERT INTO core.inventory_movements (id_movimiento, id_variante, tipo, cantidad, costo_unitario, referencia_tipo, referencia_id, fecha) VALUES (${m.id_movimiento}, ${m.id_variante}, '${m.tipo}', ${m.cantidad}, ${m.costo_unitario}, '${m.referencia_tipo}', ${m.referencia_id}, '${m.fecha.toISOString()}');\n`;
      });

      sql += `\nCOMMIT;`;

      const fileName = `inventory_movements_${this.getFormattedDate()}.sql`;
      const filePath = path.join(this.backupPath, fileName);

      await fs.writeFile(filePath, sql);

      return {
        message: `Backup de inventory_movements completado. Total: ${movements.length} registros`,
        file: fileName,
      };
    } catch (error) {
      this.logger.error('Error en backup:', error);
      throw new BadRequestException('Error al realizar backup');
    }
  }

  //! backup full database
  async backupFullDatabase(): Promise<{ message: string; file: string }> {
    try {
      this.logger.log('Iniciando backup completo...');

      const fileName = `full_backup_${this.getFormattedDate()}.sql`;
      const filePath = path.join(this.backupPath, fileName);
      const dbUrl = this.configService.get('DATABASE_URL_BACKUP');

      const command = `pg_dump "${dbUrl}" --format=plain --file="${filePath}"`;

      const { stderr } = await execAsync(command);

      if (stderr) this.logger.warn('pg_dump warnings:', stderr);

      const stats = await fs.stat(filePath);
      const sizeMB = (stats.size / 1024 / 1024).toFixed(2);

      return {
        message: `Backup completo creado. Tamaño: ${sizeMB} MB`,
        file: fileName,
      };
    } catch (error) {
      this.logger.error('Error en backup completo:', error);
      throw new BadRequestException('Error al realizar backup completo');
    }
  }

  //! listar backups
  async listBackups(): Promise<{ backups: string[] }> {
    try {
      const files = await fs.readdir(this.backupPath);
      const backups = files.filter((file) => file.endsWith('.sql'));
      return { backups };
    } catch {
      return { backups: [] };
    }
  }

  //! obtener ruta de archivo
  async getBackupFilePath(filename: string): Promise<string> {
    const filePath = path.join(this.backupPath, filename);
    try {
      await fs.access(filePath);
      return filePath;
    } catch {
      throw new Error('Archivo no encontrado');
    }
  }

  //! obtener tamaños
  async getBackupSizes(filenames: string[]): Promise<Record<string, string>> {
    const sizes: Record<string, string> = {};

    for (const filename of filenames) {
      try {
        const filePath = path.join(this.backupPath, filename);
        const stats = await fs.stat(filePath);
        const sizeInBytes = stats.size;

        if (sizeInBytes < 1024) {
          sizes[filename] = sizeInBytes + ' B';
        } else if (sizeInBytes < 1024 * 1024) {
          const sizeInKB = sizeInBytes / 1024;
          sizes[filename] = sizeInKB.toFixed(2) + ' KB';
        } else {
          const sizeInMB = sizeInBytes / (1024 * 1024);
          sizes[filename] = sizeInMB.toFixed(2) + ' MB';
        }
      } catch {
        sizes[filename] = '0 B';
      }
    }

    return sizes;
  }

  //! backup de tablas críticas
  async backupCriticalTables(): Promise<{ message: string; file: string }> {
    try {
      this.logger.log('Iniciando backup de tablas críticas...');

      const date = this.getFormattedDate();
      const fileName = `critical_tables_${date}.sql`;
      const filePath = path.join(this.backupPath, fileName);

      let sql = `-- BACKUP DE TABLAS CRÍTICAS\n`;
      sql += `-- Fecha: ${new Date().toLocaleString()}\n\n`;
      sql += `BEGIN;\n\n`;

      for (const table of this.criticalTables) {
        sql += `-- Tabla: ${table}\n`;

        const data = await this.inventoryMovementsRepository.query(
          `SELECT * FROM core.${table}`,
        );

        if (data.length > 0) {
          const columns = Object.keys(data[0]).join(', ');

          for (const row of data) {
            const values = Object.values(row)
              .map((val) => {
                if (val === null) return 'NULL';
                if (typeof val === 'string')
                  return `'${val.replace(/'/g, "''")}'`;
                if (val instanceof Date) return `'${val.toISOString()}'`;
                if (typeof val === 'boolean') return val ? 'true' : 'false';
                return val;
              })
              .join(', ');

            sql += `INSERT INTO core.${table} (${columns}) VALUES (${values});\n`;
          }
          sql += `\n`;
        }
      }

      sql += `COMMIT;`;

      await fs.writeFile(filePath, sql);

      const stats = await fs.stat(filePath);
      const size =
        stats.size < 1024 * 1024
          ? (stats.size / 1024).toFixed(2) + ' KB'
          : (stats.size / (1024 * 1024)).toFixed(2) + ' MB';

      return {
        message: `Backup de tablas críticas creado. Tamaño: ${size}`,
        file: fileName,
      };
    } catch (error) {
      this.logger.error('Error en backup crítico:', error);
      throw new BadRequestException('Error al crear backup crítico');
    }
  }

  //! backup automático a las 3 AM
  //@Cron('0 3 * * *')
  @Cron('0 2 * * *') // Ejecuta a las 22:30 (10:30 PM)
  async scheduledCriticalBackup() {
    this.logger.log('Ejecutando backup crítico automático...');
    try {
      await this.backupCriticalTables();
      this.logger.log('Backup crítico completado');
    } catch (error) {
      this.logger.error('Error en backup crítico automático:', error);
    }
  }
}
