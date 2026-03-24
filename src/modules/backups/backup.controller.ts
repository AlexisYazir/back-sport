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

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('monitor/connections')
  async connections() {
    return this.backupService.getActiveConnections();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('monitor/locks')
  async locks() {
    return this.backupService.getDetailedLocks();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('monitor/block-locks')
  async getBlockingLocks() {
    return this.backupService.getBlockingLocks();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('monitor/long-queries')
  async longQueries() {
    return this.backupService.getLongRunningQueries();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('monitor/explain')
  async explain() {
    return this.backupService.explainOrdersWithUsers();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('stats/most-queried')
  async getMostQueriedTables() {
    return this.backupService.getMostQueriedTables();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('stats/table-sizes')
  async getTableSizes() {
    return this.backupService.getTableSizes();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('stats/index-info')
  async getIndexInfo() {
    return this.backupService.getIndexInfo();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('stats/lock-stats')
  async getTableLockStats() {
    return this.backupService.getTableLockStats();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(3)
  @Get('stats/scan-stats')
  async getTableScanStats() {
    return this.backupService.getTableScanStats();
  }
}