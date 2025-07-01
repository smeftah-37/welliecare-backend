import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import * as fs from 'fs';
import { RedisModule } from 'src/redis/redis.module';
import { AuthService } from './auth.service';
import { JwtStrategy } from './jwt.strategy';
import { JwtAuthGuard } from './auth.guard';
import { AuthController } from './auth.controller';
import { NodemailerService } from 'src/utils/sendMail.service';
import { User } from 'src/entities/user.entity';



@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => {
        // Use asymmetric keys for production
        const useAsymmetric = configService.get('USE_ASYMMETRIC_JWT', 'false') === 'true';
        
        if (useAsymmetric) {
          return {
            publicKey: fs.readFileSync(
              configService.get('JWT_PUBLIC_KEY_PATH', 'keys/public.pem')
            ),
            privateKey: fs.readFileSync(
              configService.get('JWT_PRIVATE_KEY_PATH', 'keys/private.pem')
            ),
            signOptions: {
              algorithm: 'RS256',
              expiresIn: configService.get('JWT_EXPIRATION', '15m'),
              issuer: configService.get('JWT_ISSUER', 'your-app'),
              audience: configService.get('JWT_AUDIENCE', 'your-users'),
            },
          };
        } else {
          // Use symmetric key for development
          return {
            secret: configService.get('JWT_SECRET'),
            signOptions: {
              expiresIn: configService.get('JWT_EXPIRATION', '15m'),
              issuer: configService.get('JWT_ISSUER', 'your-app'),
              audience: configService.get('JWT_AUDIENCE', 'your-users'),
            },
          };
        }
      },
    }),
    // ThrottlerModule.forRootAsync({
    //   imports: [ConfigModule],
    //   inject: [ConfigService],
    //   useFactory: (config: ConfigService) => ({
    //     throttlers: [
    //       {
    //         name: 'auth-short',
    //         ttl: config.get('AUTH_THROTTLE_TTL_SHORT', 60000), // 1 minute
    //         limit: config.get('AUTH_THROTTLE_LIMIT_SHORT', 10), // 5 attempts
    //       },
    //       {
    //         name: 'auth-long',
    //         ttl: config.get('AUTH_THROTTLE_TTL_LONG', 900000), // 15 minutes
    //         limit: config.get('AUTH_THROTTLE_LIMIT_LONG', 15), // 10 attempts
    //       },
    //     ],
    //   }),
    // }),
    TypeOrmModule.forFeature([User]),
    RedisModule,
  ],
  providers: [AuthService, JwtStrategy, JwtAuthGuard,NodemailerService],
  controllers: [AuthController],
  exports: [AuthService, JwtAuthGuard],
})
export class AuthModule {}