import { Module, MiddlewareConsumer, NestModule } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { IastMiddleware } from '../iast-agent';

import { UsersModule } from './modules/users/users.module';
import { ProductsModule } from './modules/products/products.module';
import { AppController } from './app.controller';
import { BackupModule } from './modules/backups/backup.module';
import { CompanyModule } from './modules/company/company.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),

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
  ],
  controllers: [AppController],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    // Aplicar el middleware IAST a todas las rutas
    consumer.apply(IastMiddleware).forRoutes('*');
  }
}
