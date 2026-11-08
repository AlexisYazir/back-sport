import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { configureHttpApplication } from './config/http-application';
import { createHttpRequestLogger } from './security/http-request-logger';
import { AccountDeletionBootstrapService } from './modules/account-deletion/account-deletion-bootstrap.service';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.get(AccountDeletionBootstrapService).prepare();

  configureHttpApplication(app);

  app.use(createHttpRequestLogger());

  await app.listen(3000);
}

void bootstrap();
