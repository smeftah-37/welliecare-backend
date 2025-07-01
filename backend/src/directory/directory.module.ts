import { Module, MiddlewareConsumer } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
// import { ThrottlerModule } from '@nestjs/throttler';
// import { CacheModule } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';

import { Professional } from '../entities/professional.entity';
import { DirectoryController } from './directory.controller';
import { DirectoryService } from './directory.service';
import { InputSanitizerMiddleware } from './inputSanitizaMiddleware';
import { User } from 'src/entities/user.entity';




@Module({
  imports: [
    TypeOrmModule.forFeature([Professional,User]),
    
    // Rate limiting configuration
    // ThrottlerModule.forRoot({
    //   ttl: 60, // 60 seconds
    //   limit: 100, // 100 requests per minute
    // }),
    
    // // Caching configuration
    // CacheModule.register({
    //   ttl: 30, // 30 seconds
    //   max: 1000, // max items in cache
    // }),
    
    ConfigModule,
    JwtModule,
  ],
  controllers: [DirectoryController],
  providers: [
    DirectoryService,
  ],
  exports: [DirectoryService],
})
export class DirectoryModule {
  configure(consumer: MiddlewareConsumer) {
    // Apply input sanitizer to all directory routes
    consumer
      .apply(InputSanitizerMiddleware)
      .forRoutes('directory');
  }
}
