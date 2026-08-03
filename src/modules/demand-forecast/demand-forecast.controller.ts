import { Controller, Get, Param, ParseIntPipe, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Roles } from '../../services/auth/roles.decorator';
import { RolesGuard } from '../../services/auth/roles.guard';
import { DemandForecastService } from './demand-forecast.service';

@Controller('demand-forecast')
@UseGuards(AuthGuard('jwt'), RolesGuard)
@Roles(3)
export class DemandForecastController {
  constructor(private readonly demandForecastService: DemandForecastService) {}

  @Get('variants/:idVariante')
  predictVariant(@Param('idVariante', ParseIntPipe) idVariante: number) {
    return this.demandForecastService.predictVariant(idVariante);
  }
}
