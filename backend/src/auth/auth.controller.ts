import { Controller, Post, Body, UseGuards, Request, HttpCode, HttpStatus, Res, Req,  ValidationPipe,
 UnauthorizedException, Get, Ip, ForbiddenException, Param, HttpException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthResponseDto, ErrorResponseDto, LoginDto, RefreshTokenDto, SendVerificationDto, VerifyCodeDto } from './auth.dto';
import { Response as ExpressResponse } from 'express';
import { ResetPasswordDto,ForgotPasswordDto } from './auth.dto';
import { Public } from './public.decorator';
import { RealIp } from './realIp.decorator';
import { JwtAuthGuard } from './auth.guard';
import { ApiBearerAuth, ApiBody, ApiCookieAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';


@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService
  ) {}

  @Post('send-verification')
  @Public()
  @HttpCode(HttpStatus.OK)
    @ApiOperation({ 
    summary: 'Envoyer un code de vérification par email',
    description: 'Envoie un code de vérification à 6 chiffres à l\'adresse email spécifiée si elle est enregistrée dans le système.'
  })
  @ApiBody({ 
    type: SendVerificationDto,
    description: 'Données nécessaires pour envoyer le code de vérification'
  })
  @ApiResponse({
    status: 200,
    description: 'Code de vérification envoyé avec succès (si l\'email existe)',
    schema: {
      type: 'object',
      properties: {
        message: {
          type: 'string',
          example: 'Si l\'email est enregistré, vous recevrez un code de vérification'
        }
      }
    }
  })
  @ApiResponse({
    status: 400,
    description: 'Données de requête invalides',
    type: ErrorResponseDto
  })
  @ApiResponse({
    status: 429,
    description: 'Trop de tentatives, veuillez réessayer plus tard',
    type: ErrorResponseDto
  })
  async sendVerification(
    @Body() sendVerificationDto: SendVerificationDto,
    @RealIp() ipAddress: string 
  ) {
    await this.authService.sendVerificationCode(sendVerificationDto.email, ipAddress);
    return { message: 'If the email is registered, you will receive a verification code' };
  }

  
  @Post('verify-and-complete')
  @Public()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ 
    summary: 'Vérifier le code et finaliser l\'inscription',
    description: 'Vérifie le code de vérification et finalise l\'inscription de l\'utilisateur avec le rôle spécifié.'
  })
  @ApiBody({ 
    type: VerifyCodeDto,
    description: 'Code de vérification, email et rôle pour finaliser l\'inscription'
  })
  @ApiResponse({
    status: 201,
    description: 'Inscription finalisée avec succès',
    type: AuthResponseDto
  })
  @ApiResponse({
    status: 400,
    description: 'Code de vérification invalide ou expiré',
    type: ErrorResponseDto
  })
  @ApiResponse({
    status: 409,
    description: 'Utilisateur déjà inscrit',
    type: ErrorResponseDto
  })
  @ApiCookieAuth('refresh_token')
  // @Throttle({ default: { limit: 5, ttl: 600 } }) // 3 attempts per 10 minutes
  async verifyAndCompleteRegistration(
    @Body() verifyCodeDto: VerifyCodeDto,
    @Res() res: ExpressResponse,
    @RealIp() ipAddress: string 
  ) {

    const result = await this.authService.verifyCodeAndRegister(
      verifyCodeDto.email,
      verifyCodeDto.code,
      verifyCodeDto.roles,
      verifyCodeDto.password,
      ipAddress,
    );

    // Set refresh token as secure cookie
    res.cookie('refresh_token', result.refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/'
    });

    return res.status(201).json({
      access_token: result.access_token,
      user: result.user,
      message: 'Registration completed successfully'
    });
  }

  @Post('login')
  @Public()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ 
    summary: 'Connexion utilisateur',
    description: 'Authentifie l\'utilisateur avec email et mot de passe, retourne un token d\'accès et définit un cookie de rafraîchissement.'
  })
  @ApiBody({ 
    type: LoginDto,
    description: 'Identifiants de connexion'
  })
  @ApiResponse({
    status: 200,
    description: 'Connexion réussie',
    type: AuthResponseDto
  })
  @ApiResponse({
    status: 400,
    description: 'Données de requête invalides',
    type: ErrorResponseDto
  })
  @ApiResponse({
    status: 401,
    description: 'Identifiants invalides',
    type: ErrorResponseDto
  })
  @ApiResponse({
    status: 429,
    description: 'Trop de tentatives de connexion',
    type: ErrorResponseDto
  })
  @ApiCookieAuth('refresh_token')
  // @Throttle({ default: { limit: 20, ttl: 300 } }) // 5 attempts per 5 minutes
  async login(
    @Body() loginDto: LoginDto,
    @Res() res: ExpressResponse,
    @RealIp() ipAddress: string 
  ) {
console.log('Login attempt from IP:', loginDto);
    const result = await this.authService.login(loginDto.email, loginDto.password, ipAddress);
    res.cookie('refresh_token', result.refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/'
    });
  
    return res.status(200).json({
      access_token: result.access_token,
      user: result.user,
      message: 'Login successful'
    });
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
   @ApiBearerAuth()
  @ApiOperation({ 
    summary: 'Déconnexion utilisateur',
    description: 'Déconnecte l\'utilisateur, invalide le token et supprime le cookie de rafraîchissement.'
  })
  @ApiResponse({
    status: 200,
    description: 'Déconnexion réussie',
    schema: {
      type: 'object',
      properties: {
        message: {
          type: 'string',
          example: 'Déconnexion réussie'
        }
      }
    }
  })
  @ApiResponse({
    status: 401,
    description: 'Non autorisé - Token invalide',
    type: ErrorResponseDto
  })
  async logout(@Request() req, @Res() res: ExpressResponse) {
    const token = req.headers.authorization?.split(' ')[1];
    await this.authService.logout(req.user.id, token);
  
    res.clearCookie('refresh_token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/'
    });
  
    return res.status(200).json({ message: 'Logged out successfully' });
  }

//   @Post('logout-all')
//   @UseGuards(JwtAuthGuard)
//   @HttpCode(HttpStatus.OK)
//   async logoutAll(@Request() req) {
//     await this.authService.logoutAll(req.user.id);
//     return { message: 'Logged out from all devices successfully' };
//   }

//   @Post('verify-token')
//   @UseGuards(JwtAuthGuard)
//   @HttpCode(HttpStatus.OK)
//   async verifyToken(@Request() req) {
//     return {
//       valid: true,
//       user: req.user
//     };
//   }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ 
    summary: 'Obtenir les informations de l\'utilisateur connecté',
    description: 'Retourne les informations du profil de l\'utilisateur actuellement connecté.'
  })
  @ApiResponse({
    status: 200,
    description: 'Informations utilisateur récupérées avec succès',
    schema: {
      type: 'object',
      properties: {
        user: {
          type: 'object',
          properties: {
            id: { type: 'string', example: 'uuid-ici' },
            email: { type: 'string', example: 'utilisateur@exemple.com' },
            roles: { type: 'string', example: 'etudiant' },
            isActive: { type: 'boolean', example: true }
          }
        }
      }
    }
  })
  @ApiResponse({
    status: 401,
    description: 'Non autorisé - Token invalide ou manquant',
    type: ErrorResponseDto
  })
  async getMe(@Request() req) {
    const user = await this.authService.getUserById(req.user.sub);
    return {
      user: {
        id: user.id,
        email: user.email,
        roles: user.roles,
        isActive: user.isActive,
      }
    };
  }
//  @Get('admin/info')
//  @Roles('admin','it') 
//   @UseGuards(JwtAuthGuard) // Your existing auth guard
//   async getAdminSecurityInfo(@Request() req) {
//     const user = req.user;
//     if (user.roles !== 'admin' && user.roles !== 'it') {
//       throw new ForbiddenException('Access denied.');
//     }
//     const adminSecurity = await this.adminSecurityService.findOneById(user.sub ) 
//     console.log('this is the admin seucrit',adminSecurity);
//     if (!adminSecurity) {
//       throw new UnauthorizedException('not found');
//     }

//     return {
//       campus: adminSecurity.campus,
//       type: adminSecurity.type,
//       adminCode: adminSecurity.adminCode,
//       hasSecretKey: !!adminSecurity.secretKey, // Don't return the actual key
//     };
//   }

  @Post('refresh')
  @Public()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ 
    summary: 'Rafraîchir le token d\'accès',
    description: 'Génère un nouveau token d\'accès à partir du token de rafraîchissement stocké dans les cookies.'
  })
  @ApiResponse({
    status: 200,
    description: 'Token rafraîchi avec succès',
    schema: {
      type: 'object',
      properties: {
        access_token: {
          type: 'string',
          example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
        },
        message: {
          type: 'string',
          example: 'Token rafraîchi avec succès'
        }
      }
    }
  })
  @ApiResponse({
    status: 401,
    description: 'Token de rafraîchissement invalide ou manquant',
    type: ErrorResponseDto
  })
  @ApiResponse({
    status: 429,
    description: 'Trop de tentatives de rafraîchissement',
    type: ErrorResponseDto
  })
  @ApiCookieAuth('refresh_token')
  // @Throttle({ default: { limit: 15, ttl: 60 } }) // 10 attempts per minute
  async refresh(
    @Request() req,
    @Res() res: ExpressResponse
  ) {
    const refreshToken = req.cookies['refresh_token'];
    
    if (!refreshToken) {
      throw new UnauthorizedException('Invalid request');
    }

    try {
      const result = await this.authService.refreshToken(refreshToken);
      if (result.refresh_token) {
        res.cookie('refresh_token', result.refresh_token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 7 * 24 * 60 * 60 * 1000,
          path: '/'
        });
      }

      return res.status(200).json({
        access_token: result.access_token,
        message: 'Token refreshed successfully'
      });
    } catch (error) {
      res.clearCookie('refresh_token');
      throw new UnauthorizedException('Invalid request');
    }
  }

//     @Post('changePassword/:userId') // Define userId as a route parameter
//   async changePassword(@Param('userId') userId: number, @Body() info: { oldPassword: string; newPassword: string; confirmPassword: string },@Request() req) {
//     if(Number(req.user.sub) !== Number(userId))
//       throw new ForbiddenException("you're not allowed to do this action")
 
//     try {
//       // Call the service method to change the password
//       return await this.authService.changePassword(userId, info.newPassword, info.oldPassword);
//     } catch (error) {
//       // Handle errors and return appropriate HTTP status codes

//       // Optionally handle other types of errors, or rethrow them
//       throw new HttpException(error.message, HttpStatus.FORBIDDEN); // Return 401 if invalid credentials
//     }
//   }
//   @Post('forgot-password')
//   @Public()
//   @HttpCode(HttpStatus.OK)
//   // @Throttle({ default: { limit: 3, ttl: 300 } }) // 3 attempts per 5 minutes (very restrictive)
//   async forgotPassword(
//     @Body() forgotPasswordDto: ForgotPasswordDto,
//     @RealIp() ipAddress: string 
//   ) {
//         if(!forgotPasswordDto.codeMassar)
//       throw new ForbiddenException('codeMassar is required');
//     await this.authService.sendPasswordResetCode(forgotPasswordDto.email, forgotPasswordDto.codeMassar,ipAddress);
//     return { 
//       message: 'If your email is registered, you will receive a password reset code shortly' 
//     };
//   }

//   // NEW: Reset Password with Code
// @Post('reset-password')
//   @Public()

//   @HttpCode(HttpStatus.OK)
//   async resetPassword(
//     @Body(ValidationPipe) dto: ResetPasswordDto,
//     @RealIp() ipAddress: string 
//   ) {
//   if(!dto.codeMassar)
//       throw new ForbiddenException('codeMassar is required');
//     await this.authService.resetPasswordWithCode(
//       dto.email,
//       dto.code,
//       dto.newPassword,
//       dto.codeMassar,
//       ipAddress
//     );
    
//     return {
//       message: 'Password has been reset successfully. You have been logged out from all devices for security.',
//       success: true,
//       data: {
//         securityActions: [
//           'Password updated',
//           'All sessions terminated',
//           'Security tokens invalidated',
//           'Login required on all devices'
//         ],
//         nextStep: 'Please log in with your new password'
//       }
//     };
//   }

}
