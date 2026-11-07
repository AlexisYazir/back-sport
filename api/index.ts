import { NestFactory } from '@nestjs/core';
import { ExpressAdapter } from '@nestjs/platform-express';
import { AppModule } from '../src/app.module';
import { configureHttpApplication } from '../src/config/http-application';

import express from 'express';
const expressApp = express();
const adapter = new ExpressAdapter(expressApp);

async function bootstrap() {
  const app = await NestFactory.create(AppModule, adapter);

  configureHttpApplication(app);
  await app.init();

  return expressApp;
}

export default bootstrap();
