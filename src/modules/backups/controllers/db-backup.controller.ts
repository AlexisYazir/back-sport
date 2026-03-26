/* eslint-disable */
import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  StreamableFile,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { RolesGuard } from '../../../services/auth/roles.guard';
import { Roles } from '../../../services/auth/roles.decorator';
import { DbBackupService } from '../services/db-backup.service';
import { CreateScheduleDto } from '../dto/create-schedule.dto';
import { CreateRetentionPolicyDto } from '../dto/create-retention-policy.dto';
import { Readable } from 'stream';

@Controller('backup')
export class DbBackupController {
  constructor(private readonly backupService: DbBackupService) {}

  @Post('create')
  createBackup() {
    return this.backupService.createFullBackup();
  }

  @Post('create-critical')
  createCriticalTablesBackup() {
    return this.backupService.createCriticalTablesBackup();
  }

  @Get('list')
  listBackups() {
    return this.backupService.listBackups();
  }

  @Get('download/:encodedKey')
  async downloadBackupByKey(
    @Param('encodedKey') encodedKey: string,
  ): Promise<StreamableFile> {
    const key = decodeURIComponent(encodedKey);
    const stream = await this.backupService.downloadBackup(key);
    const fileName = key.split('/').pop() ?? 'backup.dump';

    return new StreamableFile(stream as Readable, {
      disposition: `attachment; filename="${fileName}"`,
      type: 'application/octet-stream',
    });
  }

  @Get('log/:encodedKey')
  getBackupLog(@Param('encodedKey') encodedKey: string) {
    return this.backupService.getBackupLog(decodeURIComponent(encodedKey));
  }

  @Delete('delete/:encodedFolderKey')
  deleteBackup(@Param('encodedFolderKey') encodedFolderKey: string) {
    return this.backupService.deleteBackup(decodeURIComponent(encodedFolderKey));
  }

  @Post('cleanup/:days')
  cleanupOldBackups(@Param('days') days: number) {
    return this.backupService.cleanupOldBackups(Number(days));
  }

  @Post('schedules')
  createSchedule(@Body() dto: CreateScheduleDto) {
    return this.backupService.createSchedule(dto);
  }

  @Get('schedules')
  listSchedules() {
    return this.backupService.listSchedules();
  }

  @Delete('schedules/:name')
  deleteSchedule(@Param('name') name: string) {
    return this.backupService.deleteSchedule(name);
  }

  @Post('retention-policies')
  createRetentionPolicy(@Body() dto: CreateRetentionPolicyDto) {
    return this.backupService.createRetentionPolicy(dto);
  }

  @Get('retention-policies')
  listRetentionPolicies() {
    return this.backupService.listRetentionPolicies();
  }

  @Delete('retention-policies/:name')
  deleteRetentionPolicy(@Param('name') name: string) {
    return this.backupService.deleteRetentionPolicy(name);
  }
}
