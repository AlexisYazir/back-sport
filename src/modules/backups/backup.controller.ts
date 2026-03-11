import { Controller, Post, Get, Param, Res } from '@nestjs/common';
import { BackupService } from './backup.service';
import type { Response } from 'express';

@Controller('backup')
export class BackupController {
  constructor(private readonly backupService: BackupService) {}

  @Post('inventory-movements')
  async backupInventoryMovements() {
    return this.backupService.backupInventoryMovements();
  }

  @Post('full')
  async backupFullDatabase() {
    return this.backupService.backupFullDatabase();
  }

  @Post('critical-tables')
  async backupCriticalTables() {
    return this.backupService.backupCriticalTables();
  }

  @Get('list')
  async listBackups() {
    return this.backupService.listBackups();
  }

  @Get('download/:filename')
  async downloadBackup(
    @Param('filename') filename: string,
    @Res() res: Response,
  ) {
    try {
      const filePath = await this.backupService.getBackupFilePath(filename);
      res.download(filePath, filename);
    } catch (error) {
      console.log(error);
      res.status(404).json({ message: 'Archivo no encontrado' });
    }
  }

  @Get('sizes')
  async getBackupSizes() {
    const backups = await this.backupService.listBackups();
    return this.backupService.getBackupSizes(backups.backups);
  }
}
