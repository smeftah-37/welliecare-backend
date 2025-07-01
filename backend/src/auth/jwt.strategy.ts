import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy, StrategyOptionsWithRequest } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { AuthService, JwtPayload } from './auth.service';
import * as fs from 'fs';
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
  ) {
    const useAsymmetric = configService.get('USE_ASYMMETRIC_JWT', 'false') === 'true';

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: useAsymmetric
        ? fs.readFileSync(configService.get('JWT_PUBLIC_KEY_PATH', 'keys/public.pem'))
        : configService.get('JWT_SECRET'),
      algorithms: useAsymmetric ? ['RS256'] : ['HS256'],
      issuer: configService.get('JWT_ISSUER', 'your-app'),
      audience: configService.get('JWT_AUDIENCE', 'your-users'),
      passReqToCallback: true, // Use StrategyOptionsWithRequest
    } as StrategyOptionsWithRequest); // Explicitly cast to StrategyOptionsWithRequest
  }

  async validate(req: any, payload: JwtPayload) {
    // Extract token from request
    const token = ExtractJwt.fromAuthHeaderAsBearerToken()(req);

    if (!token) {
      throw new UnauthorizedException('No token found');
    }

    // Check if token is blacklisted
    const user = await this.authService.validateJwtPayload(payload);
    
    if (!user) {
      throw new UnauthorizedException('Invalid token');
    }

    return {
      sub: payload.sub,
      email: payload.email,
      roles: payload.roles,
      jti: payload.jti,
    };
  }       
}
