import { NestFactory, Reflector } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import * as session from 'express-session'
import passport from 'passport';
import { RolesGuard } from './autorization/roles.guard';

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
      name: 'backEnd',
      secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: true,
      cookie: {
        // secure: true,
        maxAge: 3600000,
      },
    }),
  )
  // app.useGlobalGuards(new RolesGuard());
  await app.listen(3000);
}
bootstrap();
