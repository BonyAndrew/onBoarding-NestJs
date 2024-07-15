import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: 'localhost',
      port: 5432,
      username: 'postgres',
      password: 'bony',
      database: 'user',
      entities: [__dirname + '/../**/*.entity.js'],
      synchronize: true
    }),
  ],
})

export class DatabaseModule {}