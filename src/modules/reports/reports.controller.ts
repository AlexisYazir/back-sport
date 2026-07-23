import {
  Body,
  Controller,
  Get,
  Header,
  HttpCode,
  Param,
  ParseIntPipe,
  Post,
  Put,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Roles } from '../../services/auth/roles.decorator';
import { RolesGuard } from '../../services/auth/roles.guard';
import { SalesReportsService } from './sales-reports.service';
import { DataMiningReportsService } from './data-mining-reports.service';
import { MlTrainingService } from './ml-training.service';
import { UpdateMlScheduleDto } from './dto/update-ml-schedule.dto';
import { RunMlTrainingDto } from './dto/run-ml-training.dto';

@Controller('reports')
@UseGuards(AuthGuard('jwt'), RolesGuard)
@Roles(3)
export class ReportsController {
  constructor(
    private readonly salesReportsService: SalesReportsService,
    private readonly dataMiningReportsService: DataMiningReportsService,
    private readonly mlTrainingService: MlTrainingService,
  ) {}

  @Get('sales')
  @Header('Cache-Control', 'private, no-store')
  getSalesReport(
    @Query('from') from?: string,
    @Query('to') to?: string,
    @Query('granularity') granularity?: string,
  ) {
    return this.salesReportsService.getSalesReport({
      from,
      to,
      granularity,
    });
  }

  @Get('data-mining/demand')
  @Header('Cache-Control', 'private, no-store')
  getDemandReport() {
    return this.dataMiningReportsService.getDemandReport();
  }

  @Get('data-mining/customer-segments')
  @Header('Cache-Control', 'private, no-store')
  getCustomerSegments() {
    return this.dataMiningReportsService.getCustomerSegments();
  }

  @Get('data-mining/training/schedules')
  @Header('Cache-Control', 'private, no-store')
  getTrainingSchedules() {
    return this.mlTrainingService.listSchedules();
  }

  @Put('data-mining/training/schedules/:id')
  updateTrainingSchedule(
    @Param('id', ParseIntPipe) id: number,
    @Body() dto: UpdateMlScheduleDto,
    @Req() req: any,
  ) {
    return this.mlTrainingService.updateSchedule(id, dto, req.user.id_usuario);
  }

  @Get('data-mining/training/runs')
  @Header('Cache-Control', 'private, no-store')
  getTrainingRuns(@Query('limit') limit?: string) {
    return this.mlTrainingService.listRuns(Number(limit || 30));
  }

  @Post('data-mining/training/run')
  @HttpCode(202)
  runTraining(@Body() dto: RunMlTrainingDto, @Req() req: any) {
    return this.mlTrainingService.startManualRun(dto, req.user.id_usuario);
  }
}
