import { NestFactory } from '@nestjs/core';
import { ExpressAdapter } from '@nestjs/platform-express';
import { AppModule } from '../src/app.module';

import express from 'express';
const expressApp = express();
const adapter = new ExpressAdapter(expressApp);

async function bootstrap() {
  const app = await NestFactory.create(AppModule, adapter);

  app.enableCors({
    origin: ['http://localhost:4200', 'https://sport-center-sitie.netlify.app'],
    methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-CSRF-Token',
      'x-csrf-token',
    ],
    credentials: true,
  });
  await app.init();

  return expressApp;
}

export default bootstrap();
