import { Controller, Get } from '@nestjs/common';

@Controller()
export class AppController {
  @Get()
  getWelcome() {
    return {
      message: '¡Backend corriendo! ',
      status: 'online',
      timestamp: new Date().toISOString(),
    };
  }
}
