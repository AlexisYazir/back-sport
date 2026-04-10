import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Roles } from '../../services/auth/roles.decorator';
import { RolesGuard } from '../../services/auth/roles.guard';
import { CloudflareLogService } from './services/cloudflare-log.service';

@Controller('logs')
@UseGuards(AuthGuard('jwt'), RolesGuard)
@Roles(3)
export class LogsController {
  constructor(private readonly logService: CloudflareLogService) {}

  @Get('dates')
  getDates() {
    return this.logService.getAvailableDates();
  }

  @Get('modules')
  getModules(@Query('date') date?: string) {
    return this.logService.getAvailableModules(date);
  }

  @Get()
  getLogs(
    @Query('date') date?: string,
    @Query('module') module?: string,
    @Query('level') level?: string,
    @Query('search') search?: string,
    @Query('page') page?: string,
    @Query('limit') limit?: string,
  ) {
    return this.logService.getLogs({
      date,
      module,
      level,
      search,
      page: page ? Number(page) : undefined,
      limit: limit ? Number(limit) : undefined,
    });
  }
}
