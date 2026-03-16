/* eslint-disable */
import {
  Controller,
  Post,
  Get,
  Delete,
  Param,
  Res,
  UseGuards,
  StreamableFile 
} from '@nestjs/common';
import { BackupService } from './backup.service';
import { AuthGuard } from '@nestjs/passport';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';
import { Readable } from 'stream';

@Controller('backup')
export class BackupController {
  constructor(private readonly backupService: BackupService) {}

  @Post('create')
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  async createBackup() {
    return this.backupService.createBackup();
  }

  @Post('create-critical')
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  async createCriticalTablesBackup() {
    return this.backupService.createCriticalTablesBackup();
  }

  @Get('list')
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  async listBackups() {
    return this.backupService.listBackups();
  }

  @Get('download/:type/:name')
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  async downloadBackup(
    @Param('type') type: string,
    @Param('name') name: string,
  ): Promise<StreamableFile> {

    const stream = await this.backupService.downloadBackup(type, name);

    const decodedName = decodeURIComponent(name);

    return new StreamableFile(stream as Readable, {
      disposition: `attachment; filename="${decodedName}"`,
      type: 'application/octet-stream',
    });
  }

  @Delete('delete/:type/:name')
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  async deleteBackup(
    @Param('type') type: string,
    @Param('name') name: string,
  ) {
    return this.backupService.deleteBackup(type, name);
  }

  @Post('cleanup/:days')
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  async cleanupOldBackups(@Param('days') days: number) {
    return this.backupService.cleanupOldBackups(Number(days));
  }
}