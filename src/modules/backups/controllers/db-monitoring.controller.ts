/* eslint-disable */
import { Controller, Get, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { RolesGuard } from '../../../services/auth/roles.guard';
import { Roles } from '../../../services/auth/roles.decorator';
import { DbMonitoringService } from '../services/db-monitoring.service';

@Controller('db-monitoring')
@UseGuards(AuthGuard('jwt'), RolesGuard)
@Roles(3)
export class DbMonitoringController {
  constructor(private readonly monitoringService: DbMonitoringService) {}

  @Get('connections')
  connections() {
    return this.monitoringService.getActiveConnections();
  }

  @Get('locks')
  locks() {
    return this.monitoringService.getDetailedLocks();
  }

  @Get('blocking-locks')
  blockingLocks() {
    return this.monitoringService.getBlockingLocks();
  }

  @Get('long-queries')
  longQueries() {
    return this.monitoringService.getLongRunningQueries();
  }

  @Get('stats/most-queried')
  mostQueried() {
    return this.monitoringService.getMostQueriedTables();
  }

  @Get('stats/table-sizes')
  tableSizes() {
    return this.monitoringService.getTableSizes();
  }

  @Get('stats/index-info')
  indexInfo() {
    return this.monitoringService.getIndexInfo();
  }

  @Get('stats/lock-stats')
  lockStats() {
    return this.monitoringService.getTableLockStats();
  }

  @Get('stats/scan-stats')
  scanStats() {
    return this.monitoringService.getTableScanStats();
  }
}
