import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { configureHttpApplication } from './config/http-application';
import { createHttpRequestLogger } from './security/http-request-logger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  configureHttpApplication(app);

  app.use(createHttpRequestLogger());

  await app.listen(3000);
}

void bootstrap();
