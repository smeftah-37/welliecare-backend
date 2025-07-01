import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule } from '@nestjs/config';
import { datasourceoptions } from './utils/data-source';
import { TypeOrmModule } from '@nestjs/typeorm';
import { APP_GUARD } from '@nestjs/core';
import { JwtAuthGuard } from './auth/auth.guard';
import { AuthModule } from './auth/auth.module';
import { UserSeederService } from './utils/user.seeders';
import { User } from './entities/user.entity';
import { DirectoryModule } from './directory/directory.module';
import { ServeStaticModule } from '@nestjs/serve-static';
import { join } from 'path';

@Module({
  imports: [


    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),

    TypeOrmModule.forRoot(datasourceoptions),
        TypeOrmModule.forFeature([User]),
    
    AuthModule,DirectoryModule,
    ServeStaticModule.forRoot({
     
       rootPath: join(process.cwd(), 'uploads'),
       serveRoot: '/uploads',
       serveStaticOptions: {
         setHeaders: (res, path) => {
           res.setHeader('Cache-Control', 'private, max-age=3600');
         },
       },
     }),
  ],
  controllers: [AppController],
  providers: [AppService,UserSeederService,
      {
      provide: APP_GUARD,
      useClass: JwtAuthGuard,
    },
  ],
})
export class AppModule {}
