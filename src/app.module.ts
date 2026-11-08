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
import { ReportsModule } from './modules/reports/reports.module';
import { DemandForecastModule } from './modules/demand-forecast/demand-forecast.module';
import { MlInferenceModule } from './modules/ml-inference/ml-inference.module';
import { ProductRecommendationsModule } from './modules/product-recommendations/product-recommendations.module';
import { postgresConnectionOptions } from './config/postgres-connection';
import { AccountDeletionModule } from './modules/account-deletion/account-deletion.module';
import { DeletionRecoveryGuard } from './modules/account-deletion/account-deletion.guards';

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
        name: 'editorConnection',
        type: 'postgres',
        ...postgresConnectionOptions(
          configService.getOrThrow<string>('DATABASE_URL_EDITOR'),
          20,
          configService.get<string>('DATABASE_SSL_CA'),
        ),
        autoLoadEntities: true,
        synchronize: false,
      }),
    }),

    // Conexión para ADMIN (migraciones y mantenimiento)
    TypeOrmModule.forRootAsync({
      name: 'adminConnection',
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        name: 'adminConnection',
        type: 'postgres',
        ...postgresConnectionOptions(
          configService.getOrThrow<string>('DATABASE_URL_ADMIN'),
          5,
          configService.get<string>('DATABASE_SSL_CA'),
        ),
        autoLoadEntities: true,
        synchronize: false,
      }),
    }),

    // Conexión para READER (parte pública, solo lectura)
    TypeOrmModule.forRootAsync({
      name: 'readerConnection',
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        name: 'readerConnection',
        type: 'postgres',
        ...postgresConnectionOptions(
          configService.getOrThrow<string>('DATABASE_URL_READER'),
          30,
          configService.get<string>('DATABASE_SSL_CA'),
        ),
        autoLoadEntities: true,
        synchronize: false,
      }),
    }),

    // Conexión para BACKUP (tareas programadas)
    TypeOrmModule.forRootAsync({
      name: 'backupConnection',
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        name: 'backupConnection',
        type: 'postgres',
        ...postgresConnectionOptions(
          configService.getOrThrow<string>('DATABASE_URL_BACKUP'),
          2,
          configService.get<string>('DATABASE_SSL_CA'),
        ),
        autoLoadEntities: true,
        synchronize: false,
      }),
    }),

    UsersModule,
    AccountDeletionModule,
    ProductsModule,
    BackupModule,
    CompanyModule,
    LogsModule,
    ReportsModule,
    MlInferenceModule,
    DemandForecastModule,
    ProductRecommendationsModule,
  ],
  controllers: [AppController],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    { provide: APP_GUARD, useClass: DeletionRecoveryGuard },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(IastMiddleware).forRoutes('*');
  }
}
