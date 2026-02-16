import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
// import { WinstonModule } from 'nest-winston';
// import { winstonLogger } from './config/winston.logger';
import morgan from 'morgan';

// npm install winston nest-winston
// npm install winston-daily-rotate-file

async function bootstrap() {
  const app = await NestFactory.create(
    AppModule, //{
    //logger: WinstonModule.createLogger({
    //   instance: winstonLogger,
    // }),
    //}
  );

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  app.enableCors({
    origin: ['http://localhost:4200', 'https://sc-ecommerce.netlify.app'],
    methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  });

  // Morgan sigue funcionando para logs HTTP
  app.use(morgan('combined'));

  await app.listen(3000);
}

void bootstrap();
