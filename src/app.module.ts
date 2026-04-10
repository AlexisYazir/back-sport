import { Module, MiddlewareConsumer, NestModule } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { IastMiddleware } from '../iast-agent';

import { UsersModule } from './modules/users/users.module';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { ProductsModule } from './modules/products/products.module';
import { AppController } from './app.controller';
import { BackupModule } from './modules/backups/backup.module';
import { CompanyModule } from './modules/company/company.module';
import { LogsModule } from './modules/logs/logs.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),

    ThrottlerModule.forRoot([
      {
        ttl: 60000, // 1 minuto
        limit: 50,
      },
    ]),

    // Configuración por defecto (EDITOR - para la app web)
    TypeOrmModule.forRootAsync({
      name: 'editorConnection',
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        url: configService.get('DATABASE_URL_EDITOR'),
        autoLoadEntities: true,
        synchronize: false,
        ssl: true,
        extra: {
          ssl: {
            rejectUnauthorized: false,
          },
          connectionLimit: 20,
        },
      }),
    }),

    // Conexión para ADMIN (migraciones y mantenimiento)
    TypeOrmModule.forRootAsync({
      name: 'adminConnection',
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        url: configService.get('DATABASE_URL_ADMIN'),
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

    // Conexión para READER (parte pública, solo lectura)
    TypeOrmModule.forRootAsync({
      name: 'readerConnection',
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        url: configService.get('DATABASE_URL_READER'),
        autoLoadEntities: true,
        synchronize: false,
        ssl: true,
        extra: {
          ssl: {
            rejectUnauthorized: false,
          },
          connectionLimit: 30,
        },
      }),
    }),

    // Conexión para BACKUP (tareas programadas)
    TypeOrmModule.forRootAsync({
      name: 'backupConnection',
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        url: configService.get('DATABASE_URL_BACKUP'),
        autoLoadEntities: true,
        synchronize: false,
        ssl: true,
        extra: {
          ssl: {
            rejectUnauthorized: false,
          },
          connectionLimit: 2,
        },
      }),
    }),

    UsersModule,
    ProductsModule,
    BackupModule,
    CompanyModule,
    LogsModule,
  ],
  controllers: [AppController],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(IastMiddleware).forRoutes('*');
  }
}
