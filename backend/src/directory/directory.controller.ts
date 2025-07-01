import { 
  Controller, 
  Get, 
  Query, 
  UseGuards, 
  ValidationPipe, 
  Request,
  UseInterceptors,
  ParseIntPipe,
  BadRequestException,
  Post,
  Body,
  ConflictException,
  InternalServerErrorException,
  UploadedFile,
  NotFoundException,
  ForbiddenException,
  Param
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiQuery, ApiResponse, ApiBearerAuth, ApiSecurity, ApiProperty, ApiParam, ApiBody } from '@nestjs/swagger';
import { DirectoryService, DirectoryQueryDto, SafeProfessionalResponse } from './directory.service';
import { JwtAuthGuard } from 'src/auth/auth.guard';
import { RoleGuard } from 'src/auth/role.guard';
import { Roles } from 'src/auth/role.decorator';
import { ProfessionalRegistrationDto } from 'src/auth/auth.dto';
import { diskStorage } from 'multer';
import { FileInterceptor } from '@nestjs/platform-express';
import * as fs from 'fs';
import { unlink } from 'fs/promises';
export class ApproveProfessionalDto {
  @ApiProperty({
    description: 'Commentaire optionnel pour la validation',
    example: 'Profil complet et documents valides',
    required: false
  })
  comment?: string;
}

// DTO for reject request body
export class RejectProfessionalDto {
  @ApiProperty({
    description: 'Raison du rejet du profil professionnel',
    example: 'Documents incomplets ou non conformes',
    required: false
  })
  reason?: string;
}

// DTO for success response
export class ProfessionalActionResponseDto {
  @ApiProperty({
    description: 'Indique si l\'action a réussi',
    example: true
  })
  success: boolean;

  @ApiProperty({
    description: 'Message de confirmation',
    example: 'Professionnel validé avec succès'
  })
  message: string;

  @ApiProperty({
    description: 'Données du professionnel mis à jour',
  })
  professional: any;
}
@ApiTags('Directory')
@Controller('directory')
export class DirectoryController {
  constructor(private readonly directoryService: DirectoryService) {}

@Post('professionals/register')
  @UseInterceptors(FileInterceptor('photo', {
    storage: diskStorage({
      destination: './uploads/professionals',
      filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, `${uniqueSuffix}-${file.originalname}`);
      },
    }),
    fileFilter: (req, file, cb) => {
      if (file.mimetype.match(/\/(jpg|jpeg|png|gif)$/)) {
        cb(null, true);
      } else {
        cb(new Error('Only image files are allowed!'), false);
      }
    },
    limits: {
      fileSize: 5 * 1024 * 1024, // 5MB limit
    },
  }))
  async registerProfessional(
    @Body(new ValidationPipe({
      transform: true,
      whitelist: false, // IMPORTANT: Set to false to allow French day names
      forbidNonWhitelisted: true,
      validateCustomDecorators: true
    })) professionalData: ProfessionalRegistrationDto,
    @UploadedFile() photo?: Express.Multer.File
  ): Promise<{
    success: boolean;
    message: string;
    professional: SafeProfessionalResponse;
    registrationId: number;
    nextSteps: string[];
  }> {
    try {
      // Validate professional data
      this.validateProfessionalData(professionalData);

      // Handle photo upload
      if (photo) {
        professionalData.profileImage = `/uploads/professionals/${photo.filename}`;
      }

      // Create professional record
      const professional = await this.directoryService.createProfessional(
        professionalData,
        undefined // Self-registration
      );

      // Notify administrators
      await this.directoryService.notifyAdminsOfNewRegistration(professional.id);

      // Return success response
      return {
        success: true,
        message: 'Inscription soumise avec succès',
        professional,
        registrationId: professional.id,
        nextSteps: [
          'Votre demande est en cours de traitement',
          'Vous recevrez un email de confirmation dans les 24-48h',
          'Vérifiez régulièrement votre boîte email (y compris les spams)',
          'Vous pourrez vous connecter une fois votre profil validé'
        ]
      };

    } catch (error) {
      // Clean up uploaded file if there was an error
      if (photo && photo.path) {
        try {
          await unlink(photo.path); // Now using the promise-based version
        } catch (unlinkError) {
          console.error('Error deleting uploaded file:', unlinkError);
        }
      }

      // Handle specific errors
      if (error instanceof BadRequestException) {
        throw error;
      }

      if (error.code === '23505') { // PostgreSQL unique constraint
        throw new ConflictException('Un professionnel avec cet email existe déjà');
      }

      // Log error for debugging
      console.error('Professional registration error:', error);

      throw new InternalServerErrorException(
        'Erreur lors de l\'inscription. Veuillez réessayer plus tard.'
      );
    }
  }
private validateProfessionalData(data: ProfessionalRegistrationDto): void {
  // Convert string coordinates to numbers if they come as strings from FormData
  if (typeof data.latitude === 'string') {
    data.latitude = parseFloat(data.latitude);
  }
  if (typeof data.longitude === 'string') {
    data.longitude = parseFloat(data.longitude);
  }

  // Parse horaires if it comes as JSON string from FormData
  if (typeof data.horaires === 'string') {
    try {
      data.horaires = JSON.parse(data.horaires);
    } catch (error) {
      throw new BadRequestException('Format d\'horaires invalide');
    }
  }

  // Rest of your existing validation...
  
  // Updated title validation to include M. and Mme
  if (!['Dr', 'Pr', 'M.', 'Mme'].includes(data.titre)) {
    throw new BadRequestException('Titre doit être "Dr", "Pr", "M." ou "Mme"');
  }

  // Make sure address is complete
  if (!data.adresse || data.adresse.trim().length < 5) {
    throw new BadRequestException('L\'adresse doit contenir au moins 5 caractères');
  }
}

// Sample corrected form data:
  @Get('professional')
  async getProfessional(@Request() req: any)
  {
    return await this.directoryService.getProfessionalById(req.user.sub);
  }



  @Get('professionals')
  async getProfessionals(@Request() req: any)
  {
    if(req.user.roles !== 'admin') {
      throw new BadRequestException('Accès interdit - droits administrateur requis');
    }
    return await this.directoryService.getAllProfessionals();
  }
  @Get('getProfessionals')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ 
    summary: 'Rechercher des professionnels avec filtres géographiques et textuels',
    description: 'Retourne une liste paginée de professionnels validés avec possibilité de recherche par proximité'
  })
  @ApiQuery({ name: 'page', required: false, type: Number, description: 'Numéro de page (défaut: 1)', example: 1 })
  @ApiQuery({ name: 'limit', required: false, type: Number, description: 'Éléments par page (défaut: 20, max: 100)', example: 20 })
  @ApiQuery({ name: 'search', required: false, type: String, description: 'Recherche textuelle', example: 'cardiologue' })
  @ApiQuery({ name: 'specialite', required: false, type: String, description: 'Filtrer par spécialité', example: 'Cardiologie' })
  @ApiQuery({ name: 'titre', required: false, enum: ['Dr', 'Pr'], description: 'Filtrer par titre' })
  @ApiQuery({ name: 'ville', required: false, type: String, description: 'Filtrer par ville', example: 'Casablanca' })
  @ApiQuery({ name: 'pays', required: false, type: String, description: 'Filtrer par pays', example: 'Maroc' })
  @ApiQuery({ name: 'latitude', required: false, type: Number, description: 'Latitude utilisateur pour recherche proximité' })
  @ApiQuery({ name: 'longitude', required: false, type: Number, description: 'Longitude utilisateur pour recherche proximité' })
  @ApiQuery({ name: 'maxDistance', required: false, type: Number, description: 'Distance max en km (défaut: 50, max: 200)' })
  @ApiResponse({
    status: 200,
    description: 'Liste des professionnels trouvés',
    schema: {
      type: 'object',
      properties: {
        data: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              id: { type: 'number' },
              titre: { type: 'string', enum: ['Dr', 'Pr'] },
              firstName: { type: 'string' },
              lastName: { type: 'string' },
              specialite: { type: 'string' },
              ville: { type: 'string' },
              addresse: { type: 'string' },
              telephoneCabinet: { type: 'string' },
              distance: { type: 'number', description: 'Distance en km (si recherche géographique)' }
            }
          }
        },
        total: { type: 'number' },
        page: { type: 'number' },
        limit: { type: 'number' },
        totalPages: { type: 'number' },
        hasMore: { type: 'boolean' }
      }
    }
  })
  @ApiResponse({ status: 400, description: 'Paramètres de requête invalides' })
  @ApiResponse({ status: 401, description: 'Token d\'authentification requis' })
  async getDirectory(
    @Query(new ValidationPipe({ 
      transform: true, 
      whitelist: true, 
      forbidNonWhitelisted: true,
      validateCustomDecorators: true
    })) query: DirectoryQueryDto,
    @Request() req: any
  ) {
    // Input validation
    this.validateDirectoryQuery(query);

    // Get user role from JWT token
    const userRole = req.user?.roles || 'user';

    return this.directoryService.findDirectory(query, userRole);
  }

  @Get('nearby')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ 
    summary: 'Trouver des professionnels à proximité',
    description: 'Retourne les professionnels validés dans un rayon donné autour d\'une position'
  })
  @ApiQuery({ name: 'latitude', required: true, type: Number, description: 'Latitude de référence' })
  @ApiQuery({ name: 'longitude', required: true, type: Number, description: 'Longitude de référence' })
  @ApiQuery({ name: 'radius', required: false, type: Number, description: 'Rayon de recherche en km (défaut: 10, max: 50)' })
  @ApiResponse({
    status: 200,
    description: 'Professionnels à proximité triés par distance',
    type: [Object]
  })
  async getNearbyProfessionals(
    @Query('latitude', new ParseIntPipe({ errorHttpStatusCode: 400 })) latitude: number,
    @Query('longitude', new ParseIntPipe({ errorHttpStatusCode: 400 })) longitude: number,
    @Query('radius') radius: number = 10,
    @Request() req: any
  ): Promise<SafeProfessionalResponse[]> {
    // Additional validation
    if (!latitude || !longitude) {
      throw new BadRequestException('Latitude et longitude sont obligatoires');
    }

    const userRole = req.user?.role || 'user';
    const safeRadius = Math.min(50, Math.max(1, Number(radius) || 10));

    return this.directoryService.getNearbyProfessionals(
      Number(latitude),
      Number(longitude),
      safeRadius,
      userRole
    );
  }

  @Get('admin/pending')
  @UseGuards(JwtAuthGuard, RoleGuard)
  @Roles('admin')
  @ApiBearerAuth()
  @ApiSecurity('admin-only')
  @ApiOperation({ 
    summary: '[ADMIN] Professionnels en attente de validation',
    description: 'Endpoint réservé aux administrateurs pour voir les professionnels en attente'
  })
  @ApiResponse({ status: 200, description: 'Liste des professionnels en attente' })
  @ApiResponse({ status: 403, description: 'Accès interdit - droits administrateur requis' })
  async getPendingProfessionals(@Request() req: any) {
    const userRole = req.user?.role;
    
    return this.directoryService.findDirectory(
      { status: 'pending', page: 1, limit: 100 }, 
      userRole
    );
  }

  @Get('stats')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Statistiques publiques du directory' })
  async getDirectoryStats() {
    // Return only non-sensitive aggregated data
    const totalValidated = await this.directoryService.findDirectory(
      { status: 'validated', limit: 1 }
    );

    return {
      totalProfessionals: totalValidated.total,
      // Add more aggregated stats as needed
    };
  }

  private validateDirectoryQuery(query: DirectoryQueryDto): void {
    // Additional business logic validation
    if (query.search && query.search.length < 2) {
      throw new BadRequestException('La recherche doit contenir au moins 2 caractères');
    }

    if (query.limit && query.limit > 100) {
      throw new BadRequestException('Le limite maximum est de 100 éléments par page');
    }

    // Validate coordinate consistency
    if ((query.latitude && !query.longitude) || (!query.latitude && query.longitude)) {
      throw new BadRequestException('Les coordonnées latitude et longitude doivent être fournies ensemble');
    }

    // Validate coordinate ranges
    if (query.latitude && (query.latitude < -90 || query.latitude > 90)) {
      throw new BadRequestException('Latitude invalide: doit être entre -90 et 90');
    }

    if (query.longitude && (query.longitude < -180 || query.longitude > 180)) {
      throw new BadRequestException('Longitude invalide: doit être entre -180 et 180');
    }

    if (query.maxDistance && query.maxDistance > 200) {
      throw new BadRequestException('Distance maximum autorisée: 200km');
    }
  }




   @Post('professionals/:id/approve')
  @UseGuards(JwtAuthGuard)
 @ApiBearerAuth()
  @ApiSecurity('admin-only')
  @ApiOperation({ 
    summary: '[ADMIN] Valider un profil professionnel',
    description: `
    Permet aux administrateurs de valider un profil professionnel en attente.
    
    **Actions effectuées :**
    - Change le statut du professionnel à 'validated'
    - Active le compte utilisateur associé
    - Enregistre un commentaire optionnel
    - Envoie une notification au professionnel (si configuré)
    
    **Permissions requises :** Administrateur uniquement
    `
  })
  @ApiParam({
    name: 'id',
    description: 'ID unique du professionnel à valider',
    type: 'number',
    example: 123
  })
  @ApiBody({
    description: 'Données optionnelles pour la validation',
    type: ApproveProfessionalDto,
    required: false,
    examples: {
      'avec_commentaire': {
        summary: 'Validation avec commentaire',
        description: 'Validation avec un commentaire explicatif',
        value: {
          comment: 'Profil complet, tous les documents sont valides'
        }
      },
      'sans_commentaire': {
        summary: 'Validation simple',
        description: 'Validation sans commentaire',
        value: {}
      }
    }
  })
  @ApiResponse({
    status: 200,
    description: 'Professionnel validé avec succès',
    type: ProfessionalActionResponseDto,
    example: {
      success: true,
      message: 'Professionnel validé avec succès',
      professional: {
        id: 123,
        titre: 'Dr',
        firstName: 'Marie',
        lastName: 'Dubois',
        email: 'marie.dubois@example.com',
        specialite: 'Cardiologue',
        status: 'validated',
        createdAt: '2024-06-30T10:00:00.000Z',
        updatedAt: '2024-06-30T15:30:00.000Z'
      }
    }
  })
  @ApiResponse({
    status: 400,
    description: 'Données invalides ou professionnel déjà validé',
    example: {
      message: 'Ce professionnel est déjà validé',
      error: 'Bad Request',
      statusCode: 400
    }
  })
  @ApiResponse({
    status: 401,
    description: 'Token d\'authentification manquant ou invalide',
    example: {
      message: 'Invalid or missing authentication token',
      error: 'Unauthorized',
      statusCode: 401
    }
  })
  @ApiResponse({
    status: 403,
    description: 'Permissions insuffisantes - Administrateur requis',
    example: {
      message: 'Seuls les administrateurs peuvent valider des professionnels',
      error: 'Forbidden',
      statusCode: 403
    }
  })
  @ApiResponse({
    status: 404,
    description: 'Professionnel non trouvé',
    example: {
      message: 'Professionnel non trouvé',
      error: 'Not Found',
      statusCode: 404
    }
  })
  async approveProfessional(
    @Param('id', ParseIntPipe) id: number,
    @Body() body: ApproveProfessionalDto,
    @Request() req: any
  ) {
    // Check admin role
    if (req.user.roles !== 'admin') {
      throw new ForbiddenException('Seuls les administrateurs peuvent valider des professionnels');
    }

    try {
      const professional = await this.directoryService.approveProfessional(id, req.user.roles);
      
      return {
        success: true,
        message: 'Professionnel validé avec succès',
        professional
      };
    } catch (error) {
      if (error.message === 'Professionnel non trouvé') {
        throw new NotFoundException('Professionnel non trouvé');
      }
      throw error;
    }
  }

  // 3. 🆕 ADD: POST /directory/professionals/:id/reject
  @Post('professionals/:id/reject')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiSecurity('admin-only')
  @ApiOperation({ 
    summary: '[ADMIN] Rejeter un profil professionnel',
    description: `
    Permet aux administrateurs de rejeter un profil professionnel en attente.
    
    **Actions effectuées :**
    - Change le statut du professionnel à 'rejected'
    - Désactive le compte utilisateur associé
    - Enregistre la raison du rejet
    - Envoie une notification au professionnel (si configuré)
    
    **Permissions requises :** Administrateur uniquement
    
    **Note :** Cette action peut être réversible selon la configuration système.
    `
  })
  @ApiParam({
    name: 'id',
    description: 'ID unique du professionnel à rejeter',
    type: 'number',
    example: 456
  })
  @ApiBody({
    description: 'Raison du rejet (optionnelle mais recommandée)',
    type: RejectProfessionalDto,
    required: false,
    examples: {
      'documents_incomplets': {
        summary: 'Documents incomplets',
        description: 'Rejet pour documents manquants ou incomplets',
        value: {
          reason: 'Documents incomplets : diplôme manquant'
        }
      },
      'informations_incorrectes': {
        summary: 'Informations incorrectes',
        description: 'Rejet pour informations non conformes',
        value: {
          reason: 'Informations personnelles non conformes aux documents fournis'
        }
      },
      'specialite_non_reconnue': {
        summary: 'Spécialité non reconnue',
        description: 'Rejet pour spécialité non autorisée',
        value: {
          reason: 'Spécialité non reconnue par l\'ordre professionnel'
        }
      },
      'sans_raison': {
        summary: 'Rejet sans raison spécifique',
        description: 'Rejet simple sans raison détaillée',
        value: {}
      }
    }
  })
  @ApiResponse({
    status: 200,
    description: 'Professionnel rejeté avec succès',
    type: ProfessionalActionResponseDto,
    example: {
      success: true,
      message: 'Professionnel rejeté avec succès',
      professional: {
        id: 456,
        titre: 'Dr',
        firstName: 'Jean',
        lastName: 'Martin',
        email: 'jean.martin@example.com',
        specialite: 'Dermatologue',
        status: 'rejected',
        validationNotes: 'Documents incomplets : diplôme manquant',
        createdAt: '2024-06-30T10:00:00.000Z',
        updatedAt: '2024-06-30T15:45:00.000Z'
      }
    }
  })
  @ApiResponse({
    status: 400,
    description: 'Données invalides ou professionnel déjà traité',
    example: {
      message: 'Ce professionnel a déjà été traité',
      error: 'Bad Request',
      statusCode: 400
    }
  })
  @ApiResponse({
    status: 401,
    description: 'Token d\'authentification manquant ou invalide',
    example: {
      message: 'Invalid or missing authentication token',
      error: 'Unauthorized',
      statusCode: 401
    }
  })
  @ApiResponse({
    status: 403,
    description: 'Permissions insuffisantes - Administrateur requis',
    example: {
      message: 'Seuls les administrateurs peuvent rejeter des professionnels',
      error: 'Forbidden',
      statusCode: 403
    }
  })
  @ApiResponse({
    status: 404,
    description: 'Professionnel non trouvé',
    example: {
      message: 'Professionnel non trouvé',
      error: 'Not Found',
      statusCode: 404
    }
  })
  async rejectProfessional(
    @Param('id', ParseIntPipe) id: number,
    @Body() body: RejectProfessionalDto,
    @Request() req: any
  ) {
    // Check admin role
    if (req.user.roles !== 'admin') {
      throw new ForbiddenException('Seuls les administrateurs peuvent rejeter des professionnels');
    }

    try {
      const professional = await this.directoryService.rejectProfessional(id, body.reason, req.user.roles);
      
      return {
        success: true,
        message: 'Professionnel rejeté avec succès',
        professional
      };
    } catch (error) {
      if (error.message === 'Professionnel non trouvé') {
        throw new NotFoundException('Professionnel non trouvé');
      }
      throw error;
    }
  }
}