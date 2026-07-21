import { Controller, Get, Header, Query, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Roles } from '../../services/auth/roles.decorator';
import { RolesGuard } from '../../services/auth/roles.guard';
import { SalesReportsService } from './sales-reports.service';

@Controller('reports')
@UseGuards(AuthGuard('jwt'), RolesGuard)
@Roles(3)
export class ReportsController {
  constructor(private readonly salesReportsService: SalesReportsService) {}

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
}
