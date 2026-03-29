import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
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

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  app.enableCors({
    origin: ['http://localhost:4200', 'https://sport-center-sitie.netlify.app'],
    methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-CSRF-Token', // Agregar este header (puede ser en minúsculas o mayúsculas)
      'x-csrf-token', // También en minúsculas por si acaso
    ],
    credentials: true,
  });

  // Morgan sigue funcionando para logs HTTP
  app.use(
    morgan(
      ':remote-addr - - [:date-mx] ":method :url HTTP/:http-version" :status :res[content-length]',
    ),
  );

  await app.listen(3000);
}

void bootstrap();
