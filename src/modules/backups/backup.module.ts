import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ScheduleModule } from '@nestjs/schedule';
import { BackupController } from './backup.controller';
import { BackupService } from './backup.service';
import { InventoryMovements } from '../products/entities/inventory/inventory_movements.entity';

@Module({
  imports: [
    ScheduleModule.forRoot(),
    TypeOrmModule.forFeature([InventoryMovements], 'readerConnection'),
  ],
  controllers: [BackupController],
  providers: [BackupService],
})
export class BackupModule {}
