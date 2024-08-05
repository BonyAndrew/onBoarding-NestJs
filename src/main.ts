import { NestFactory, Reflector } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import * as session from 'express-session';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
    })
  )
  app.use(
    session({
      // name: 'backEnd',
      secret: process.env.SESSION_SECRET,
      resave: true,
      saveUninitialized: true,
      cookie: {
        // secure: true,
        maxAge: 3600000,
      },
    }),
  )
  await app.listen(3000);
}
bootstrap();
