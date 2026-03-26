import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import morgan from 'morgan';

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
  app.use(morgan('common'));

  await app.listen(3000);
}

void bootstrap();
