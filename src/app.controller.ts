import { Controller, Get } from '@nestjs/common';

@Controller()
export class AppController {
  @Get()
  getWelcome() {
    return {
      message: '¡Backend corriendo! ',
      status: 'online',
      timestamp: new Date().toISOString(),
      documentation: '¡API REST funcionando correctamente!',
    };
  }

  @Get('health')
  getHealth() {
    return {
      status: 'ok',
      database: 'connected',
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
    };
  }
}
