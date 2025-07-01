import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import * as cookieParser from 'cookie-parser';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser());
  app.enableCors({
    origin: [process.env.url_front,'http://localhost:3000','http://localhost:8081'],

    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  });
  app.useGlobalPipes(new ValidationPipe());
    const config = new DocumentBuilder()
      .setTitle('WellieCare Directory API')
      .setDescription('API sécurisée pour la gestion de l\'annuaire de professionnels de santé')
      .setVersion('1.0')
      .addBearerAuth()
      .addSecurity('api-key', {
        type: 'apiKey',
        in: 'header',
        name: 'X-API-Key',
      })
      .build();
    
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api/docs', app, document);
  
    // app.setGlobalPrefix('api');
  await app.listen(process.env.PORT ?? 8080);
}
bootstrap();
