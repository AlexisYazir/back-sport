import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
// import { HttpLoggerMiddleware } from './config/http-logger.middleware';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
// import { WinstonModule } from 'nest-winston';
// import * as winston from 'winston';

import { UsersModule } from './modules/users/users.module';
import { ProductsModule } from './modules/products/products.module';
import { AppController } from './app.controller';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),

    // LOGGER CONFIGURATION
    // WinstonModule.forRoot({
    //   transports: [
    //     new winston.transports.Console(),

    //     new winston.transports.File({
    //       filename: 'logs/error.log',
    //       level: 'error',
    //     }),

    //     new winston.transports.File({
    //       filename: 'logs/combined.log',
    //     }),
    //   ],
    //   format: winston.format.combine(
    //     winston.format.timestamp(),
    //     winston.format.errors({ stack: true }),
    //     winston.format.json(),
    //   ),
    // }),

    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        url: configService.get('DATABASE_URL'),
        autoLoadEntities: true,
        synchronize: false,
        ssl: true,
        extra: {
          ssl: {
            rejectUnauthorized: false,
          },
          connectionLimit: 5,
        },
      }),
    }),

    UsersModule,
    ProductsModule,
  ],
  controllers: [AppController],
})
export class AppModule {}
// implements NestModule {
//   configure(consumer: MiddlewareConsumer) {
//     consumer.apply(HttpLoggerMiddleware).forRoutes('*');
//   }
// }
