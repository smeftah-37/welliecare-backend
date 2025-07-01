import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtAuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService
  ) {}

  // Generate access token
  async generateAccessToken(payload: any): Promise<string> {
    return this.jwtService.sign(payload);
  }

  // Generate refresh token with longer expiration
  async generateRefreshToken(payload: any): Promise<string> {
    return this.jwtService.sign(
      { ...payload, tokenType: 'refresh' },
      {
        expiresIn: this.configService.get('JWT_REFRESH_EXPIRATION', '7d'),
        secret: this.configService.get('JWT_REFRESH_SECRET'),
      }
    );
  }

  // Verify access token
  async verifyAccessToken(token: string): Promise<any> {
    return this.jwtService.verify(token);
  }

  // Verify refresh token
  async verifyRefreshToken(token: string): Promise<any> {
    return this.jwtService.verify(token, {
      secret: this.configService.get('JWT_REFRESH_SECRET'),
    });
  }
}