import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  //  habilitar validaciones en todos los DTOs
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // ignora campos que no estén en el DTO
      forbidNonWhitelisted: true, // lanza error si llega un campo no permitido
      transform: true, // convierte los tipos automáticamente
    }),
  );

  // Habilitar CORS para permitir peticiones desde el frontend (Angular en :4200)
  app.enableCors({
    origin: ['http://localhost:4200'],
    methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  });

  await app.listen(3000);
}
bootstrap();