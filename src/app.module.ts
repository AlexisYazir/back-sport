import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { UsersModule } from './users/users.module';
import { AppController } from './app.controller'; // ← Agrega esta línea

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),

    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        url: configService.get('DATABASE_URL'), // Usará el NUEVO connection string
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
  ],
  controllers: [AppController], // ← Agrega esta línea
})
export class AppModule {}
