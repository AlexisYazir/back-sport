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

  await app.listen(3000);
}
bootstrap();
