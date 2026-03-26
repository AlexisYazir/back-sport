/* eslint-disable */
import { Body, Controller, Delete, Get, Param, Post, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { RolesGuard } from '../../../services/auth/roles.guard';
import { Roles } from '../../../services/auth/roles.decorator';
import { DbMaintenanceService } from '../services/db-maintenance.service';
import { CreateScheduleDto } from '../dto/create-schedule.dto';

@Controller('db-maintenance')
@UseGuards(AuthGuard('jwt'), RolesGuard)
@Roles(3)
export class DbMaintenanceController {
  constructor(private readonly maintenanceService: DbMaintenanceService) {}

  @Post('vacuum')
  runVacuum() {
    return this.maintenanceService.runVacuumAnalyze('manual');
  }

  @Get('vacuum/logs')
  listVacuumLogs() {
    return this.maintenanceService.listVacuumLogs();
  }

  @Get('vacuum/log/:encodedKey')
  getVacuumLog(@Param('encodedKey') encodedKey: string) {
    return this.maintenanceService.getVacuumLog(decodeURIComponent(encodedKey));
  }

  @Post('vacuum/schedules')
  createVacuumSchedule(@Body() dto: CreateScheduleDto) {
    return this.maintenanceService.createVacuumSchedule(dto);
  }

  @Get('vacuum/schedules')
  listVacuumSchedules() {
    return this.maintenanceService.listVacuumSchedules();
  }

  @Delete('vacuum/schedules/:name')
  deleteVacuumSchedule(@Param('name') name: string) {
    return this.maintenanceService.deleteVacuumSchedule(name);
  }
}
