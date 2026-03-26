import { Controller, Get } from '@nestjs/common';

@Controller()
export class AppController {
  @Get()
  getWelcome() {
    return {
      message: 'Backend corriendo!',
      status: 'online',
      timestamp: new Date().toISOString(),
    };
  }

  @Get('healthz')
  getHealthcheck() {
    return {
      ok: true,
      service: 'sport-center-backend',
      timestamp: new Date().toISOString(),
    };
  }
}
