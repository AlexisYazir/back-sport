/* eslint-disable */
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Cron } from '@nestjs/schedule';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';
import {
  S3Client,
  PutObjectCommand,
  ListObjectsV2Command,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
} from '@aws-sdk/client-s3';

const execAsync = promisify(exec);

@Injectable()
export class BackupService {
  private readonly logger = new Logger(BackupService.name);
  private readonly s3: S3Client;
  private readonly isProduction: boolean;

  constructor(private readonly configService: ConfigService) {
    this.s3 = new S3Client({
      region: 'auto',
      endpoint: this.configService.get<string>('R2_ENDPOINT')!,
      credentials: {
        accessKeyId: this.configService.get<string>('R2_ACCESS_KEY_ID')!,
        secretAccessKey: this.configService.get<string>('R2_SECRET_ACCESS_KEY')!,
      },
    });
    this.isProduction = process.env.NODE_ENV === 'production';
  }

  private getBucket() {
    return this.configService.get('R2_BUCKET');
  }

  private getFormattedDate(): string {
    const d = new Date();
    return `${d.getFullYear()}-${(d.getMonth()+1).toString().padStart(2,'0')}-${d.getDate()
      .toString().padStart(2,'0')}_${d.getHours().toString().padStart(2,'0')}-${d.getMinutes().toString().padStart(2,'0')}`;
  }

  // =====================================================
  // CREATE FULL BACKUP - AHORA CON DETECCIÓN DE ENTORNO
  // =====================================================
  async createBackup() {
    // 🚨 EN PRODUCCIÓN (Vercel) - NO ejecutar pg_dump
    if (this.isProduction) {
      this.logger.log('📦 En producción: los backups automáticos los maneja GitHub Actions');
      return { 
        success: false, 
        message: 'Los backups automáticos los maneja GitHub Actions',
        info: 'Los backups se crean diariamente a las 3 AM',
        action: 'Usa GitHub Actions para crear backups'
      };
    }

    // 🖥️ EN DESARROLLO LOCAL - Ejecutar pg_dump normalmente
    const dbUrl = this.configService.get('DATABASE_URL_BACKUP');
    const filename = `full/backup_${this.getFormattedDate()}.dump`;
    const tempPath = path.join(process.cwd(), filename.replace('/','_'));

    try {
      this.logger.log('📦 Creating full database backup (local)');

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

  // =====================================================
  // CREATE CRITICAL TABLES BACKUP - CON DETECCIÓN
  // =====================================================
  async createCriticalTablesBackup() {
    // 🚨 EN PRODUCCIÓN (Vercel) - NO ejecutar pg_dump
    if (this.isProduction) {
      this.logger.log('📦 En producción: los backups críticos los maneja GitHub Actions');
      return { 
        success: false, 
        message: 'Los backups críticos los maneja GitHub Actions',
        info: 'Los backups se crean diariamente a las 3 AM',
        action: 'Usa GitHub Actions para crear backups'
      };
    }

    // 🖥️ EN DESARROLLO LOCAL - Ejecutar pg_dump normalmente
    this.logger.log('📦 Creating critical tables backup (local)');
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
    const tempPath = path.join(process.cwd(), filename.replace('/','_'));

    try {
      const tableFlags = tables.map(t => `-t ${t}`).join(' ');

      await execAsync(
        `pg_dump -Fc ${tableFlags} "${dbUrl}" -f "${tempPath}"`,
      );

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

  // =====================================================
  // LIST BACKUPS - SIN CAMBIOS
  // =====================================================
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

  // =====================================================
  // DOWNLOAD BACKUP - SIN CAMBIOS
  // =====================================================
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

  // =====================================================
  // DELETE BACKUP - SIN CAMBIOS
  // =====================================================
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

  // =====================================================
  // DAILY CRON - SOLO PARA DESARROLLO LOCAL
  // =====================================================
  @Cron('0 3 * * *')
  async scheduledDailyBackup() {
    // En producción, GitHub Actions maneja esto
    if (this.isProduction) {
      this.logger.log('⏰ GitHub Actions maneja los backups programados');
      return;
    }

    this.logger.log('⏰ Running daily backup (local)');
    await this.createBackup();
    await this.createCriticalTablesBackup();
    await this.cleanupOldBackups(7);
  }

  // =====================================================
  // DELETE OLD BACKUPS - SIN CAMBIOS
  // =====================================================
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
        this.logger.log(`🗑 deleting old backup ${obj.Key}`);

        await this.s3.send(
          new DeleteObjectCommand({
            Bucket: this.getBucket(),
            Key: obj.Key,
          }),
        );
      }
    }
  }
}