import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { UsersModule } from './users/users.module';

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
        url: configService.get('DATABASE_URL'), // ✅ Usa la URL completa
        autoLoadEntities: true,
        synchronize: configService.get('NODE_ENV') !== 'production', // ✅ Solo sync en desarrollo
        ssl: {
          rejectUnauthorized: false,
        },
        extra: {
          ssl: {
            rejectUnauthorized: false,
          },
        },
      }),
    }),

    UsersModule,
  ],
})
export class AppModule {}
