import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ScheduleModule } from '@nestjs/schedule';
import { InventoryMovements } from '../products/entities/inventory/inventory_movements.entity';
import { DbBackupController } from './controllers/db-backup.controller';
import { DbMonitoringController } from './controllers/db-monitoring.controller';
import { DbMaintenanceController } from './controllers/db-maintenance.controller';
import { DbBackupService } from './services/db-backup.service';
import { DbMonitoringService } from './services/db-monitoring.service';
import { DbMaintenanceService } from './services/db-maintenance.service';
import { R2StorageService } from './services/r2-storage.service';
import { BackupScheduleEntity } from './entities/backup-schedule.entity';
import { VacuumScheduleEntity } from './entities/vacuum-schedule.entity';
import { BackupRetentionPolicyEntity } from './entities/backup-retention-policy.entity';

@Module({
  imports: [
    ScheduleModule.forRoot(),
    TypeOrmModule.forFeature([InventoryMovements], 'readerConnection'),
    TypeOrmModule.forFeature(
      [BackupScheduleEntity, VacuumScheduleEntity, BackupRetentionPolicyEntity],
      'adminConnection',
    ),
  ],
  controllers: [DbBackupController, DbMonitoringController, DbMaintenanceController],
  providers: [DbBackupService, DbMonitoringService, DbMaintenanceService, R2StorageService],
})
export class BackupModule {}
