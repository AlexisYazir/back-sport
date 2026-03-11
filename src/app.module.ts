import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';

import { UsersModule } from './modules/users/users.module';
import { ProductsModule } from './modules/products/products.module';
import { AppController } from './app.controller';
import { BackupModule } from './modules/backups/backup.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),

    // Configuración por defecto (EDITOR - para la app web)
    TypeOrmModule.forRootAsync({
      name: 'editorConnection', // Nombre para identificar la conexión
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
          connectionLimit: 20, // Más conexiones para editor
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
        synchronize: false, // ¡NUNCA true en producción!
        ssl: true,
        extra: {
          ssl: {
            rejectUnauthorized: false,
          },
          connectionLimit: 5, // Pocas conexiones para admin
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
          connectionLimit: 30, // Muchas conexiones para lecturas
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
          connectionLimit: 2, // Muy pocas conexiones para backup
        },
      }),
    }),

    UsersModule,
    ProductsModule,
    BackupModule,
  ],
  controllers: [AppController],
})
export class AppModule {}
