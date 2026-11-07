import { ValidationPipe, type INestApplication } from '@nestjs/common';

export function configureHttpApplication(app: INestApplication): void {
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  app.enableCors({
    origin: [
      'http://localhost:4200',
      'https://sport-center-sitie.netlify.app',
      'http://localhost:8081',
      'http://localhost:19006',
      'http://front-sport-rust.vercel.app',
    ],
    methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-CSRF-Token',
      'x-csrf-token',
      'X-Auth-Retry',
    ],
    credentials: true,
  });
}
