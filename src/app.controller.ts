import { Controller, Get } from '@nestjs/common';

@Controller()
export class AppController {
  getHello(): any {
    throw new Error('Method not implemented.');
  }
  @Get()
  getWelcome() {
    return {
      message: '¡Backend corriendo! ',
      status: 'online',
      timestamp: new Date().toISOString(),
    };
  }
}
