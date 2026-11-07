import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { configureHttpApplication } from './config/http-application';
import morgan from 'morgan';

const APP_TIME_ZONE = 'America/Mexico_City';

morgan.token('date-mx', () =>
  new Intl.DateTimeFormat('en-GB', {
    timeZone: APP_TIME_ZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
    .format(new Date())
    .replace(',', ''),
);

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  configureHttpApplication(app);

  // Morgan sigue funcionando para logs HTTP
  app.use(
    morgan(
      ':remote-addr - - [:date-mx] ":method :url HTTP/:http-version" :status :res[content-length]',
    ),
  );

  await app.listen(3000);
}

void bootstrap();
