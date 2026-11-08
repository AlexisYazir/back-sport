import { NestFactory } from '@nestjs/core';
import { ExpressAdapter } from '@nestjs/platform-express';
import { AppModule } from '../src/app.module';
import { configureHttpApplication } from '../src/config/http-application';
import { AccountDeletionBootstrapService } from '../src/modules/account-deletion/account-deletion-bootstrap.service';

import express from 'express';
const expressApp = express();
const adapter = new ExpressAdapter(expressApp);

async function bootstrap() {
  const app = await NestFactory.create(AppModule, adapter);
  await app.get(AccountDeletionBootstrapService).prepare();

  configureHttpApplication(app);
  await app.init();

  return expressApp;
}

export default bootstrap();
