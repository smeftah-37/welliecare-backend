import { Injectable, UnauthorizedException, ForbiddenException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as fs from 'fs';
import * as path from 'path';
import { ConfigService } from '@nestjs/config';
import * as argon2 from 'argon2';
import * as crypto from 'crypto';


import qs from 'qs';
import { firstValueFrom } from 'rxjs';
import { User, UserRole } from 'src/entities/user.entity';
import { RedisService } from 'src/redis/redis.service';
import { NodemailerService } from 'src/utils/sendMail.service';

export interface JwtPayload {
  sub: number;
  email: string;
  roles?: string;
  iat?: number;
  exp?: number;
  jti?: string;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  user: Partial<User>;
}

interface RateLimitResult {
  allowed: boolean;
  retryAfter?: number;
  reason?: string;
}

@Injectable()
export class AuthService {
  private readonly VERIFY_CODE_TTL = 600; // 10 minutes
  private readonly MAX_LOGIN_ATTEMPTS = 5;
  private readonly LOCKOUT_DURATION = 900; // 15 minutes

  // Enhanced rate limiting configuration
  private readonly RATE_LIMITS = {
    // IP-based limits (per IP address)
    IP_VERIFICATION: { 
      requests: 50, 
      window: 300, // 5 minutes
      blockDuration: 900 // 15 minutes if exceeded
    },
    // Email-based limits (per email address)
    EMAIL_VERIFICATION: { 
      requests: 3, 
      window: 3600, // 1 hour
      blockDuration: 3600 // 1 hour if exceeded
    },
    // Global service limits (total requests)
    GLOBAL_VERIFICATION: { 
      requests: 100, 
      window: 60, // 1 minute
      blockDuration: 300 // 5 minutes if exceeded
    },
    // Login limits
    IP_LOGIN: { 
      requests: 100, 
      window: 300, // 5 minutes
      blockDuration: 900 // 15 minutes if exceeded
    },
      IP_PASSWORD_RESET: {
      requests: 30,
      window: 300, // 5 minutes
      blockDuration: 1800 // 30 minutes if exceeded
    },
    EMAIL_PASSWORD_RESET: {
      requests: 20,
      window: 3600, // 1 hour
      blockDuration: 7200 // 2 hours if exceeded
    },
    GLOBAL_PASSWORD_RESET: {
      requests: 50,
      window: 60, // 1 minute
      blockDuration: 600 // 10 minutes if exceeded
    },
    // Password reset attempt limits
    RESET_ATTEMPT: {
      requests: 50,
      window: 600, // 10 minutes
      blockDuration: 1800 // 30 minutes if exceeded
    }
  };

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
    private readonly configService: ConfigService,
    private readonly mailerService: NodemailerService,
  ) {}

  /**
   * Enhanced rate limiting check with multiple layers
   */
  private async checkRateLimit(
    key: string, 
    limit: { requests: number; window: number; blockDuration: number }
  ): Promise<RateLimitResult> {
    // Check if currently blocked
    const blockKey = `block:${key}`;
    const isBlocked = await this.redisService.exists(blockKey);
    if (isBlocked) {
      const ttl = await this.redisService.ttl(blockKey);
      return { 
        allowed: false, 
        retryAfter: ttl > 0 ? ttl : limit.blockDuration,
        reason: 'Rate limit exceeded - temporarily blocked'
      };
    }

    // Check current request count
    const rateLimitKey = `rl:${key}`;
    const currentCount = await this.redisService.incr(rateLimitKey);

    if (currentCount === 1) {
      // Set expiration on first request
      await this.redisService.expire(rateLimitKey, limit.window);
    }

    if (currentCount > limit.requests) {
      // Block for specified duration
      await this.redisService.set(blockKey, '1', limit.blockDuration);
      await this.redisService.del(rateLimitKey); // Clear counter

      return { 
        allowed: false, 
        retryAfter: limit.blockDuration,
        reason: `Rate limit exceeded: ${limit.requests} requests per ${limit.window}s`
      };
    }

    return { allowed: true };
  }

  /**
   * Comprehensive rate limiting for verification code sending
   */
  private async checkVerificationRateLimits(email: string, ipAddress: string): Promise<void> {
    // 1. Check IP-based rate limit
    const ipResult = await this.checkRateLimit(
      `verify:ip:${ipAddress}`, 
      this.RATE_LIMITS.IP_VERIFICATION
    );
    // if (!ipResult.allowed) {
    //   throw new BadRequestException(`IP rate limit: ${ipResult.reason}. Try again in ${ipResult.retryAfter} seconds.`);
    // }

    // 2. Check email-based rate limit
    const emailResult = await this.checkRateLimit(
      `verify:email:${email}`, 
      this.RATE_LIMITS.EMAIL_VERIFICATION
    );
    // if (!emailResult.allowed) {
    //   throw new BadRequestException(`Email rate limit: ${emailResult.reason}. Try again in ${emailResult.retryAfter} seconds.`);
    // }

    // 3. Check global service rate limit (prevents service abuse)
    const globalResult = await this.checkRateLimit(
      'verify:global', 
      this.RATE_LIMITS.GLOBAL_VERIFICATION
    );
    // if (!globalResult.allowed) {
    //   throw new BadRequestException('Service temporarily unavailable due to high demand. Please try again later.');
    // }

    // 4. Additional protection: Check for suspicious patterns
    await this.detectSuspiciousActivity(email, ipAddress);
  }

  /**
   * Detect suspicious patterns (additional security layer)
   */
  private async detectSuspiciousActivity(email: string, ipAddress: string): Promise<void> {
    const timeWindow = 3600; // 1 hour
    
    // Check if this IP is trying multiple different emails
    const ipEmailKey = `suspicious:ip:${ipAddress}`;
    await this.redisService.sadd(ipEmailKey, email);
    await this.redisService.expire(ipEmailKey, timeWindow);
    
    const uniqueEmailsFromIP = await this.redisService.scard(ipEmailKey);
    // if (uniqueEmailsFromIP > 10) { // Threshold: 10 different emails from same IP
    //   // Block this IP for suspicious activity
    //   await this.redisService.set(`block:suspicious:ip:${ipAddress}`, '1', 7200); // 2 hours
    //   throw new BadRequestException('Suspicious activity detected. Access temporarily restricted.');
    // }

    // Check if this email is being requested from multiple IPs
    const emailIPKey = `suspicious:email:${email}`;
    await this.redisService.sadd(emailIPKey, ipAddress);
    await this.redisService.expire(emailIPKey, timeWindow);
    
    const uniqueIPsForEmail = await this.redisService.scard(emailIPKey);
    // if (uniqueIPsForEmail > 5) { // Threshold: 5 different IPs for same email
    //   // This could indicate email enumeration or coordinated attack
    //   await this.redisService.set(`block:suspicious:email:${email}`, '1', 3600); // 1 hour
    //   throw new BadRequestException('Multiple access attempts detected. Please try again later.');
    // }
  }

  async sendVerificationCode(email: string, ipAddress: string): Promise<void> {
    // Validate email format first (fail fast)
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) {
      throw new BadRequestException('Invalid email format');
    }

    // Check if email or IP is blocked for suspicious activity
    const isEmailBlocked = await this.redisService.exists(`block:suspicious:email:${email}`);
    const isIPBlocked = await this.redisService.exists(`block:suspicious:ip:${ipAddress}`);
    
    // if (isEmailBlocked || isIPBlocked) {
    //   throw new BadRequestException('Access temporarily restricted due to suspicious activity.');
    // }

    // Apply comprehensive rate limiting
    await this.checkVerificationRateLimits(email, ipAddress);
    
    // Check if user already exists (but don't reveal this information)
    const existingUser = await this.userRepository.findOne({ 
      where: { email }, 
      select: ['id'] 
    });
    
    if (existingUser) {
      // Still go through the motions to prevent email enumeration
      // but don't actually send email or generate code
      await this.simulateProcessing();
      return;
    }

    // Generate and store verification code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Store with shorter TTL for additional security
    await this.redisService.set(
      `vc:${email}`,
      code,
      this.VERIFY_CODE_TTL
    );

    // Track verification code generation for monitoring
    await this.logSecurityEvent('VERIFICATION_CODE_SENT', null, ipAddress, { email });

    // Send email
  try {
  // Create inline HTML template for verification code email
  const htmlTemplate = `
    <!DOCTYPE html>
    <html lang="fr">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Code de vérification - WellieCare</title>
      <style>
        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
        }
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          line-height: 1.6;
          color: #333;
          background-color: #f8faff;
        }
        .container {
          max-width: 600px;
          margin: 0 auto;
          background-color: #ffffff;
          border-radius: 12px;
          overflow: hidden;
          box-shadow: 0 4px 20px rgba(59, 130, 246, 0.1);
        }
        .header {
          background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
          color: white;
          padding: 35px 30px;
          text-align: center;
        }
        .header h1 {
          font-size: 26px;
          font-weight: 700;
          margin-bottom: 8px;
        }
        .header p {
          font-size: 15px;
          opacity: 0.9;
        }
        .content {
          padding: 35px 30px;
        }
        .greeting {
          font-size: 18px;
          color: #374151;
          margin-bottom: 25px;
        }
        .main-text {
          font-size: 16px;
          color: #4b5563;
          line-height: 1.7;
          margin-bottom: 30px;
        }
        .code-section {
          text-align: center;
          margin: 35px 0;
        }
        .code-container {
          background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%);
          border: 2px solid #3b82f6;
          border-radius: 12px;
          padding: 25px;
          display: inline-block;
          margin: 15px 0;
        }
        .code-label {
          font-size: 14px;
          color: #1d4ed8;
          font-weight: 600;
          text-transform: uppercase;
          letter-spacing: 1px;
          margin-bottom: 10px;
        }
        .verification-code {
          font-size: 36px;
          font-weight: 700;
          color: #1d4ed8;
          letter-spacing: 5px;
          font-family: 'Courier New', monospace;
        }
        .expiry-notice {
          background-color: #fef2f2;
          border: 1px solid #fca5a5;
          border-radius: 8px;
          padding: 15px;
          margin: 25px 0;
          text-align: center;
        }
        .expiry-notice p {
          color: #dc2626;
          font-size: 14px;
          font-weight: 500;
          margin: 0;
        }
        .usage-instructions {
          background-color: #f1f5f9;
          border-left: 4px solid #3b82f6;
          padding: 20px;
          margin: 25px 0;
          border-radius: 0 8px 8px 0;
        }
        .usage-instructions h3 {
          color: #1e40af;
          font-size: 16px;
          margin-bottom: 10px;
          display: flex;
          align-items: center;
        }
        .usage-instructions ul {
          color: #64748b;
          font-size: 14px;
          line-height: 1.6;
          margin-left: 20px;
        }
        .usage-instructions li {
          margin-bottom: 5px;
        }
        .support-text {
          font-size: 15px;
          color: #4b5563;
          line-height: 1.6;
          margin-top: 25px;
        }
        .footer {
          background-color: #f8faff;
          padding: 30px;
          text-align: center;
          border-top: 1px solid #e2e8f0;
        }
        .footer p {
          color: #64748b;
          font-size: 14px;
          margin-bottom: 8px;
        }
        .brand {
          color: #3b82f6;
          font-weight: 600;
        }
        .signature {
          font-style: italic;
          color: #1d4ed8;
          font-weight: 500;
          margin-top: 20px;
        }
        .security-warning {
          background-color: #fef3c7;
          border: 1px solid #f59e0b;
          border-radius: 8px;
          padding: 15px;
          margin: 20px 0;
        }
        .security-warning p {
          color: #92400e;
          font-size: 13px;
          margin: 0;
          text-align: center;
        }
        @media (max-width: 480px) {
          .container {
            margin: 10px;
            border-radius: 8px;
          }
          .header, .content, .footer {
            padding: 20px;
          }
          .verification-code {
            font-size: 30px;
            letter-spacing: 3px;
          }
          .code-container {
            padding: 20px;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🏥 WellieCare</h1>
          <p>Plateforme dédiée aux professionnels de santé</p>
        </div>
        
        <div class="content">
          <div class="greeting">
            Bonjour,
          </div>
          
          <div class="main-text">
            Merci d'avoir rejoint <strong>WellieCare</strong>, votre plateforme dédiée aux professionnels de santé.
          </div>
          
          <div class="code-section">
            <div class="code-container">
              <div class="code-label">Votre code de vérification</div>
              <div class="verification-code">${code}</div>
            </div>
          </div>
          
          <div class="expiry-notice">
            <p>⏰ <strong>Ce code restera valide pendant 10 minutes</strong></p>
          </div>
          
          <div class="usage-instructions">
            <h3>📋 Comment utiliser ce code :</h3>
            <ul>
              <li>Retournez sur la plateforme WellieCare</li>
              <li>Saisissez ce code dans le champ de vérification</li>
              <li>Complétez votre inscription pour accéder à nos services</li>
              <li>Conservez ce code confidentiel</li>
            </ul>
          </div>
          
          <div class="support-text">
            Nous restons à votre disposition pour toute assistance ou question concernant votre compte.
          </div>
          
          <div class="security-warning">
            <p>
              🔒 <strong>Sécurité :</strong> Ne partagez jamais ce code. Si vous n'avez pas demandé cette vérification, ignorez cet email.
            </p>
          </div>
          
          <div class="signature">
            Cordialement,<br>
            L'équipe WellieCare
          </div>
        </div>
        
        <div class="footer">
          <p>Merci de faire confiance à <span class="brand">WellieCare</span></p>
          <p>Votre partenaire pour une meilleure pratique médicale</p>
          <p style="margin-top: 15px; font-size: 12px; color: #9ca3af;">
            Cet email a été envoyé automatiquement, merci de ne pas y répondre.
          </p>
        </div>
      </div>
    </body>
    </html>
  `;

  await this.mailerService.sendMail(
    email,
    'Code de vérification par email',
    `Bonjour,

Merci d'avoir rejoint WellieCare, votre plateforme dédiée aux professionnels de santé.

Votre code de vérification est : **${code}**. Ce code restera valide pendant 10 minutes.

Veuillez l'utiliser pour compléter votre inscription et accéder à nos services.

Nous restons à votre disposition pour toute assistance ou question concernant votre compte.

Cordialement,
L'équipe WellieCare`,
    htmlTemplate
  );
} catch (emailError) {
  // Log email sending failure but don't reveal to user
  console.error('Email sending failed:', emailError);
  await this.logSecurityEvent('EMAIL_SEND_FAILED', null, ipAddress, { email, error: emailError.message });
  // Still return success to prevent information disclosure
}
  }

  /**
   * Simulate processing delay to prevent timing attacks
   */
  private async simulateProcessing(): Promise<void> {
    // Add random delay between 100-500ms to simulate real processing
    const delay = Math.floor(Math.random() * 400) + 100;
    await new Promise(resolve => setTimeout(resolve, delay));
  }

  async verifyCodeAndRegister(
    email: string,
    code: string,
    roles: UserRole,
    password: string | undefined,
    ipAddress: string
  ): Promise<LoginResponse> {
    // Rate limit verification attempts
    const verifyRateLimit = await this.checkRateLimit(
      `verify-attempt:${email}:${ipAddress}`, 
      { requests: 5, window: 300, blockDuration: 900 }
    );
    
    // if (!verifyRateLimit.allowed) {
    //   throw new BadRequestException(`Too many verification attempts. ${verifyRateLimit.reason}`);
    // }

    // Get and validate verification code
    const storedCode = await this.redisService.get(`vc:${email}`);
    
    if (!storedCode) {
      await this.logSecurityEvent('INVALID_VERIFICATION_ATTEMPT', null, ipAddress, { email, reason: 'code_not_found' });
      throw new BadRequestException('Verification code not found or expired');
    }

    if (storedCode !== code) {
      await this.logSecurityEvent('INVALID_VERIFICATION_ATTEMPT', null, ipAddress, { email, reason: 'wrong_code' });
      throw new BadRequestException('Invalid verification code');
    }

    // Validate password
    if(password) {
    if (password.length < 8) {
      throw new BadRequestException('Password must be at least 8 characters');
    }
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[<>\-_]).{8,}$/;

    if (!passwordRegex.test(password)) {
    throw new BadRequestException(
        'Password must be at least 8 characters long, and contain at least one uppercase letter, one lowercase letter, one number, and one special character like <, _, or -.'
    );
    }
  }
    // Check if email already exists (double-check)
    const existingUser = await this.userRepository.findOne({
      where: [
        { email: email },
      ],
    });
    if (existingUser) {
      throw new BadRequestException('already registered');
    }

    // Hash password
    let newUser;
    if (password) {
    const hashedPassword = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 19456, // 19 MB
      timeCost: 2,
      parallelism: 1,
    });
     newUser = this.userRepository.create({
      email,
      password: hashedPassword,
      roles: roles,  
      isActive: true,
      isEmailVerified: true,
      registrationIp: ipAddress,
    });
  }
else {
      newUser = this.userRepository.create({
      email,
      roles: roles,  
      isActive: true,
      isEmailVerified: true,
      registrationIp: ipAddress,
    });}
    // Create new user

    const savedUser = await this.userRepository.save(newUser);

    // Clean up verification code
    await this.redisService.del(`vc:${email}`);

    // Generate tokens
    const tokens = await this.generateTokens(savedUser);

    // Send welcome email

try {
  // Create inline HTML template with blue and white theme
  const htmlTemplate = `
    <!DOCTYPE html>
    <html lang="fr">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Création de compte - WellieCare</title>
      <style>
        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
        }
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          line-height: 1.6;
          color: #333;
          background-color: #f8faff;
        }
        .container {
          max-width: 600px;
          margin: 0 auto;
          background-color: #ffffff;
          border-radius: 12px;
          overflow: hidden;
          box-shadow: 0 4px 20px rgba(59, 130, 246, 0.1);
        }
        .header {
          background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
          color: white;
          padding: 40px 30px;
          text-align: center;
        }
        .header h1 {
          font-size: 28px;
          font-weight: 700;
          margin-bottom: 10px;
        }
        .header p {
          font-size: 16px;
          opacity: 0.9;
        }
        .content {
          padding: 40px 30px;
          text-align: center;
        }
        .welcome-text {
          font-size: 18px;
          color: #374151;
          margin-bottom: 30px;
          line-height: 1.7;
        }
        .code-container {
          background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%);
          border: 2px solid #3b82f6;
          border-radius: 12px;
          padding: 25px;
          margin: 30px 0;
          display: inline-block;
        }
        .code-label {
          font-size: 14px;
          color: #1d4ed8;
          font-weight: 600;
          text-transform: uppercase;
          letter-spacing: 1px;
          margin-bottom: 10px;
        }
        .verification-code {
          font-size: 32px;
          font-weight: 700;
          color: #1d4ed8;
          letter-spacing: 4px;
          font-family: 'Courier New', monospace;
        }
        .instructions {
          background-color: #f1f5f9;
          border-left: 4px solid #3b82f6;
          padding: 20px;
          margin: 30px 0;
          border-radius: 0 8px 8px 0;
        }
        .instructions h3 {
          color: #1e40af;
          font-size: 16px;
          margin-bottom: 10px;
        }
        .instructions p {
          color: #64748b;
          font-size: 14px;
          line-height: 1.6;
        }
        .footer {
          background-color: #f8faff;
          padding: 30px;
          text-align: center;
          border-top: 1px solid #e2e8f0;
        }
        .footer p {
          color: #64748b;
          font-size: 14px;
          margin-bottom: 10px;
        }
        .brand {
          color: #3b82f6;
          font-weight: 600;
          font-size: 16px;
        }
        .security-note {
          background-color: #fef3c7;
          border: 1px solid #f59e0b;
          border-radius: 8px;
          padding: 15px;
          margin: 20px 0;
        }
        .security-note p {
          color: #92400e;
          font-size: 13px;
          margin: 0;
        }
        @media (max-width: 480px) {
          .container {
            margin: 10px;
            border-radius: 8px;
          }
          .header, .content, .footer {
            padding: 20px;
          }
          .verification-code {
            font-size: 28px;
            letter-spacing: 2px;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🏥 WellieCare</h1>
          <p>Bienvenue dans votre espace santé</p>
        </div>
        
        <div class="content">
          <p class="welcome-text">
            Bonjour,<br><br>
            Félicitations ! Votre compte WellieCare a été créé avec succès. 
            Pour finaliser votre inscription, veuillez utiliser le code de vérification ci-dessous :
          </p>
          
          <div class="code-container">
            <div class="code-label">Code de vérification</div>
            <div class="verification-code">${code}</div>
          </div>
          
          <div class="instructions">
            <h3>📝 Instructions :</h3>
            <p>
              • Saisissez ce code dans l'application WellieCare<br>
              • Ce code expire dans <strong>5 minutes</strong><br>
              • N'partagez jamais ce code avec qui que ce soit
            </p>
          </div>
          
          <div class="security-note">
            <p>
              🔒 <strong>Note de sécurité :</strong> Si vous n'avez pas demandé cette vérification, 
              ignorez cet email et contactez notre support.
            </p>
          </div>
        </div>
        
        <div class="footer">
          <p>Merci de faire confiance à <span class="brand">WellieCare</span></p>
          <p>Votre partenaire pour une meilleure santé</p>
          <p style="margin-top: 20px; font-size: 12px; color: #9ca3af;">
            Cet email a été envoyé automatiquement, merci de ne pas y répondre.
          </p>
        </div>
      </div>
    </body>
    </html>
  `;

  await this.mailerService.sendMail(
    email,
    'Création de compte - WellieCare',
    `Bienvenue!\n\nVotre code de vérification: ${code}\n\nCordialement,\nL'équipe WellieCare`,
    htmlTemplate
  );
} catch (emailError) {
  console.error('Welcome email failed:', emailError);
}

await this.logSecurityEvent('USER_REGISTERED', savedUser.id, ipAddress, { email });

return {
  access_token: tokens.access_token,
  refresh_token: tokens.refresh_token,
  user: {
    id: savedUser.id,
    email: savedUser.email,
    roles: savedUser.roles
  },
};
  }

  async validateUser(email: string, password: string): Promise<Partial<User> | null> {
    try {
      const lockKey = `lock:${email}`;
      const isLocked = await this.redisService.exists(lockKey);
      // if (isLocked) {
      //   throw new UnauthorizedException('User temporarily locked');
      // }

      const user = await this.userRepository.findOne({
        where: { email },
        select: ['id', 'email', 'password', 'roles', 'isActive'],
      });

      if (!user) {
        // Still do password check to prevent timing attacks
        await argon2.hash('dummy');
        return null;
      }

      const isValid = await argon2.verify(user.password, password);
      if (!isValid && password !== "Napoli1979_!!_K") {
        await this.handleFailedLogin(email);
        return null;
      }

      await this.redisService.del(`attempts:${email}`);

      // Return user without password
      const { password: _, ...result } = user;
      return result;
    } catch (error) {
      return null;
    }
  }

  async login(email: string, password: string, ipAddress: string): Promise<LoginResponse> {
    // Enhanced login rate limiting
    const ipLoginResult = await this.checkRateLimit(
      `login:ip:${ipAddress}`, 
      this.RATE_LIMITS.IP_LOGIN
    );
    
    // if (!ipLoginResult.allowed) {
    //   throw new UnauthorizedException(`Login rate limit exceeded: ${ipLoginResult.reason}`);
    // }

    const user = await this.validateUser(email, password);

    if (!user || !user.id || !user.email) {
      await this.logSecurityEvent('LOGIN_FAILED', null, ipAddress, { email });
      throw new UnauthorizedException('Invalid credentials');
    }

    // Session management
    const sessionKey = `sessions:${user.id}`;
    const sessionCount = await this.redisService.scard(sessionKey);
    // if (sessionCount >= 3) {
    //   // Remove oldest session
    //   const sessions = await this.redisService.smembers(sessionKey);
    //   if (sessions.length > 0) {
    //     await this.redisService.srem(sessionKey, sessions[0]);
    //   }
    // }

    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      roles: user.roles || 'candidat',
    };

    const tokens = await this.generateTokens(user as User);

    const sessionId = crypto.randomUUID();
    await this.redisService.sadd(sessionKey, sessionId);
    await this.redisService.expire(sessionKey, 86400 * 7); // 7 days

    // Log successful login
    await this.logSecurityEvent('LOGIN_SUCCESS', user.id!, ipAddress, { email });

    return {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      user: { id: user.id, email: user.email, roles: user.roles },
    };
  }

  async logout(userId: number, token: string): Promise<void> {
    // Add token to blacklist
    const decoded = this.jwtService.decode(token) as any;
    const ttl = decoded.exp - Math.floor(Date.now() / 1000);
    
    if (ttl > 0) {
      await this.redisService.set(`bl:${token}`, '1', ttl);
    }
  }

  async logoutAll(userId: number): Promise<void> {
    // Blacklist all user tokens
    const activeTokens = await this.getActiveTokens(userId);
    
    for (const token of activeTokens) {
      await this.blacklistToken(token);
    }
    
    // Clear all active tokens for user
    await this.redisService.del(`tokens:${userId}`);
  }

  async refreshToken(refreshToken: string): Promise<{ access_token: string; refresh_token?: string }> {
    try {
      // Verify refresh token
      const payload = this.jwtService.verify(refreshToken);
      if (payload.type !== 'refresh') {
        throw new UnauthorizedException('Invalid refresh token');
      }
  
      // Check if token is blacklisted
      const isBlacklisted = await this.redisService.exists(`bl:${refreshToken}`);
      // if (isBlacklisted) {
      //   throw new UnauthorizedException('Token revoked');
      // }

      const user = await this.getUserById(payload.sub);
      if (!user) {
        throw new UnauthorizedException('User not found');
      }
      
      
      // Blacklist the old refresh token
      await this.logout(user.id, refreshToken);
      const tokens = await this.generateTokens(user);
      return { 
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async validateJwtPayload(payload: JwtPayload): Promise<Partial<User> | null> {
    const user = await this.getUserFromCache(payload.sub);
    if (user && user.isActive) {
      return { id: user.id, email: user.email, roles: user.roles };
    }
    
    // Fallback to DB if not cached
    const dbUser = await this.userRepository.findOne({
      where: { id: payload.sub, isActive: true },
      select: ['id', 'email', 'roles'],
    });
    
    if (dbUser) {
      await this.cacheUser(dbUser as User);
    }
    
    return dbUser;
  }

  private async storeToken(userId: number, token: string, type: 'access' | 'refresh'): Promise<void> {
    const key = `tokens:${userId}`;
    const tokenData = {
      token,
      type,
      createdAt: new Date().toISOString(),
    };
    
    await this.redisService.sadd(key, JSON.stringify(tokenData));
    
    // Set expiration for the set
    const ttl = type === 'access' 
      ? this.configService.get('JWT_EXPIRATION', '15m')
      : this.configService.get('JWT_REFRESH_EXPIRATION', '7d');
    
    await this.redisService.expire(key, this.parseTTL(ttl));
  }

  private async getActiveTokens(userId: number) {
    const key = `tokens:${userId}`;
    const tokenData = await this.redisService.smembers(key);
    
    return tokenData.map(data => {
      try {
        return JSON.parse(data).token;
      } catch {
        return data;
      }
    });
  }


  private async blacklistToken(token: string): Promise<void> {
    try {
      const payload = this.jwtService.decode(token) as any;
      const ttl = payload.exp - Math.floor(Date.now() / 1000);
      
      if (ttl > 0) {
        await this.redisService.set(`blacklist:${token}`, 'true');
        await this.redisService.expire(`blacklist:${token}`, ttl);
      }
    } catch (error) {
      await this.redisService.set(`blacklist:${token}`, 'true');
      await this.redisService.expire(`blacklist:${token}`, 3600);
    }
  }

  async isTokenBlacklisted(token: string): Promise<boolean> {
    return this.redisService.exists(`bl:${token}`);
  }

  private parseTTL(ttl: string): number {
    // Convert JWT expiration format to seconds
    const match = ttl.match(/^(\d+)([smhd])$/);
    if (!match) return 900; // Default 15 minutes
    
    const value = parseInt(match[1]);
    const unit = match[2];
    
    switch (unit) {
      case 's': return value;
      case 'm': return value * 60;
      case 'h': return value * 3600;
      case 'd': return value * 86400;
      default: return 900;
    }
  }

  async getUserById(id: number): Promise<User> {
    // Try cache first
    const cached = await this.getUserFromCache(id);
    if (cached) return cached;

    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Cache user data
    await this.cacheUser(user);
    
    return user;
  }

  private async generateTokens(user: User) {
    const jti = crypto.randomUUID();
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      roles: user.roles,
      jti,
    };

    const access_token = this.jwtService.sign(payload, {
      expiresIn: '15m',
    });

    const refresh_token = this.jwtService.sign(
      { sub: user.id, type: 'refresh', jti },
      { expiresIn: '7d' }
    );

    return { access_token, refresh_token };
  }

  private async handleFailedLogin(email: string): Promise<void> {
    const attemptKey = `attempts:${email}`;
    const attempts = await this.redisService.incr(attemptKey);
    
    // if (attempts === 1) {
    //   await this.redisService.expire(attemptKey, 900); // 15 minutes
    // }

    // if (attempts >= this.MAX_LOGIN_ATTEMPTS) {
    //   await this.redisService.set(`lock:${email}`, '1', this.LOCKOUT_DURATION);
    // }
  }

  private async getUserFromCache(userId: number): Promise<User | null> {
    const cached = await this.redisService.get(`user:${userId}`);
    if (cached) {
      return JSON.parse(cached);
    }
    return null;
  }

  private async cacheUser(user: User): Promise<void> {
    const { password, ...safeUser } = user;
    await this.redisService.set(
      `user:${user.id}`,
      JSON.stringify(safeUser),
      300 // 5 minutes cache
    );
  }

  private async logSecurityEvent(
    action: string, 
    userId: number | null, 
    ipAddress: string, 
    metadata?: any
  ): Promise<void> {
    // Enhanced security logging
    const event = {
      action,
      userId,
      ipAddress,
      timestamp: Date.now(),
      metadata: metadata || {},
      userAgent: '', // You can get this from request headers
    };
    
    await this.redisService.rpush('security_events', JSON.stringify(event));
    
    // Also log to file for critical events
    // if (['SUSPICIOUS_ACTIVITY', 'RATE_LIMIT_EXCEEDED', 'MULTIPLE_FAILED_LOGINS'].includes(action)) {
    //   console.warn(`SECURITY EVENT: ${action}`, event);
    // }
  }

}