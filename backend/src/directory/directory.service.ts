import { Injectable, BadRequestException, ForbiddenException, ConflictException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, SelectQueryBuilder } from 'typeorm';
import { Professional, WeeklySchedule } from '../entities/professional.entity';
import { User, UserRole } from '../entities/user.entity';
import { IsOptional, IsNumber, IsString, IsEnum, Min, Max, Length, IsLatitude, IsLongitude, ValidateIf } from 'class-validator';
import { Transform, Type } from 'class-transformer';
import { ProfessionalRegistrationDto } from 'src/auth/auth.dto';
import * as argon2 from 'argon2';

export class DirectoryQueryDto {
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(1)
  @Max(1000)
  page?: number = 1;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(1)
  @Max(100)
  limit?: number = 20;

  @IsOptional()
  @IsString()
  @Length(2, 100)
  @Transform(({ value }) => value?.trim().replace(/[<>\"'%;()&+]/g, ''))
  search?: string;

  @IsOptional()
  @IsString()
  @Length(2, 50)
  @Transform(({ value }) => value?.trim())
  specialite?: string;

  @IsOptional()
  @IsEnum(['Dr', 'Pr', 'M.', 'Mme'])
  titre?: 'Dr' | 'Pr' | 'M.' | 'Mme';

  @IsOptional()
  @IsString()
  @Length(2, 50)
  @Transform(({ value }) => value?.trim())
  pays?: string;

  @IsOptional()
  @IsString()
  @Length(2, 50)
  @Transform(({ value }) => value?.trim())
  ville?: string;

  @IsOptional()
  @Type(() => Number)
  @IsLatitude()
  latitude?: number;

  @IsOptional()
  @Type(() => Number)
  @IsLongitude()
  longitude?: number;

  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(1)
  @Max(200)
  @ValidateIf((o) => o.latitude && o.longitude)
  maxDistance?: number = 50;

  @IsOptional()
  @IsEnum(['pending', 'validated', 'rejected'])
  status?: 'pending' | 'validated' | 'rejected' = 'validated';
}

export interface SafeProfessionalResponse {
  id: number;
  titre: string;
  firstName: string;
  lastName: string;
  specialite: string;
  specialiteAutre?: string;
  pays: string;
  ville: string;
  adresse: string;
  codePostal?: string;
  telephoneCabinet: string;
  status: string;
  distance?: number;
  createdAt: Date;
  profileImage?: string;
  horaires?: WeeklySchedule;
}

export interface DirectoryResponse {
  data: SafeProfessionalResponse[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
  hasMore: boolean;
}

@Injectable()
export class DirectoryService {
  constructor(
    @InjectRepository(Professional)
    private professionalRepository: Repository<Professional>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  async createProfessional(
    professionalData: ProfessionalRegistrationDto,
    adminUserId?: number
  ): Promise<SafeProfessionalResponse> {
    // Check if email already exists in professionals table
    const existingProfessional = await this.professionalRepository.findOne({
      where: { email: professionalData.email }
    });

    if (existingProfessional) {
      throw new ConflictException('Un professionnel avec cet email existe déjà');
    }

    // Hash the password
    const hashedPassword = await argon2.hash(professionalData.password, {
      type: argon2.argon2id,
      memoryCost: 19456,
      timeCost: 2,
      parallelism: 1,
    });

    // Find the user account (should exist from OTP verification)
    const userAccount = await this.userRepository.findOne({
      where: { email: professionalData.email }
    });

    if (!userAccount) {
      throw new BadRequestException('Utilisateur non trouvé pour l\'email fourni');
    }

    // Update user password
    userAccount.password = hashedPassword;
    const savedUser = await this.userRepository.save(userAccount);

    // Create professional profile
    const professional = this.professionalRepository.create({
      titre: professionalData.titre,
      firstName: professionalData.firstName,
      lastName: professionalData.lastName,
      email: professionalData.email,
      password: hashedPassword,
      specialite: professionalData.specialite,
      specialiteAutre: professionalData.specialiteAutre,
      pays: professionalData.pays,
      ville: professionalData.ville,
      adresse: professionalData.adresse,
      codePostal: professionalData.codePostal,
      telephoneCabinet: professionalData.telephoneCabinet,
      telephonePortable: professionalData.telephonePortable,
      latitude: professionalData.latitude,
      longitude: professionalData.longitude,
      profileImage: professionalData.profileImage,
      horaires: professionalData.horaires,
      status: adminUserId ? 'validated' : 'pending',
      account: savedUser,
      accountId: savedUser.id
    });

    // REMOVED: Don't call updateLocationFromCoordinates() - it causes PostGIS error
    // if (professional.latitude && professional.longitude) {
    //   professional.updateLocationFromCoordinates();
    // }

    // Update search vector before saving
    if (professional.firstName || professional.lastName || professional.specialite || professional.ville || professional.adresse) {
      await this.updateSearchVector(professional);
    }

    const savedProfessional = await this.professionalRepository.save(professional);

    // If admin-created and validated, activate the user account
    if (adminUserId && professional.status === 'validated') {
      savedUser.isActive = true;
      await this.userRepository.save(savedUser);
    }

    return this.mapToSafeResponse([savedProfessional])[0];
  }

  async notifyAdminsOfNewRegistration(professionalId: number): Promise<void> {
    console.log(`New professional registration: ${professionalId}`);
    // TODO: Implement actual notification logic
  }

  async findDirectory(query: DirectoryQueryDto, userRole?: string): Promise<DirectoryResponse> {
    this.validateLocationInput(query);

    const {
      page = 1,
      limit = 20,
      search,
      specialite,
      titre,
      pays,
      ville,
      latitude,
      longitude,
      maxDistance = 50,
      status = 'validated'
    } = query;

    if (status !== 'validated' && userRole !== 'admin') {
      throw new ForbiddenException('Accès non autorisé aux professionnels non validés');
    }

    const skip = (page - 1) * limit;

    let queryBuilder = this.createSecureQueryBuilder();
    
    queryBuilder.where('professional.status = :status', { status });

    this.applyFilters(queryBuilder, { specialite, titre, pays, ville });
    this.applySecureSearch(queryBuilder, search);
    this.applyLocationFilter(queryBuilder, latitude, longitude, maxDistance);

    const total = await this.getSecureCount(queryBuilder);

    const professionals = await queryBuilder
      .skip(skip)
      .take(limit)
      .getRawAndEntities();

    const data = this.mapToSafeResponse(professionals.entities, latitude, longitude, professionals.raw);

    return {
      data,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
      hasMore: page < Math.ceil(total / limit)
    };
  }

  private validateLocationInput(query: DirectoryQueryDto): void {
    const { latitude, longitude } = query;
    
    if ((latitude && !longitude) || (!latitude && longitude)) {
      throw new BadRequestException('Les coordonnées latitude et longitude doivent être fournies ensemble');
    }

    if (latitude !== undefined && (latitude < -90 || latitude > 90)) {
      throw new BadRequestException('Latitude invalide: doit être entre -90 et 90');
    }

    if (longitude !== undefined && (longitude < -180 || longitude > 180)) {
      throw new BadRequestException('Longitude invalide: doit être entre -180 et 180');
    }
  }

  private createSecureQueryBuilder(): SelectQueryBuilder<Professional> {
    return this.professionalRepository
      .createQueryBuilder('professional')
      .select([
        'professional.id',
        'professional.titre',
        'professional.firstName',
        'professional.lastName',
        'professional.specialite',
        'professional.specialiteAutre',
        'professional.pays',
        'professional.ville',
        'professional.adresse',
        'professional.codePostal',
        'professional.telephoneCabinet',
        'professional.latitude',
        'professional.longitude',
        'professional.status',
        'professional.profileImage',
        'professional.horaires',
        'professional.createdAt'
      ]);
  }

  private applyFilters(
    queryBuilder: SelectQueryBuilder<Professional>,
    filters: { specialite?: string; titre?: string; pays?: string; ville?: string }
  ): void {
    const { specialite, titre, pays, ville } = filters;

    if (specialite) {
      queryBuilder.andWhere('LOWER(professional.specialite) = LOWER(:specialite)', { specialite });
    }

    if (titre) {
      queryBuilder.andWhere('professional.titre = :titre', { titre });
    }

    if (pays) {
      queryBuilder.andWhere('LOWER(professional.pays) = LOWER(:pays)', { pays });
    }

    if (ville) {
      queryBuilder.andWhere('LOWER(professional.ville) = LOWER(:ville)', { ville });
    }
  }

  private applySecureSearch(queryBuilder: SelectQueryBuilder<Professional>, search?: string): void {
    if (!search) return;

    const sanitizedSearch = search.replace(/[<>\"'%;()&+]/g, '').trim();
    
    if (sanitizedSearch.length < 2) {
      throw new BadRequestException('La recherche doit contenir au moins 2 caractères');
    }

    queryBuilder.andWhere(`
      (
        to_tsvector('french', 
          coalesce(professional.firstName, '') || ' ' || 
          coalesce(professional.lastName, '') || ' ' || 
          coalesce(professional.specialite, '') || ' ' || 
          coalesce(professional.specialiteAutre, '') || ' ' || 
          coalesce(professional.ville, '') || ' ' ||
          coalesce(professional.adresse, '')
        ) @@ plainto_tsquery('french', :search)
        OR LOWER(professional.firstName) LIKE LOWER(:searchLike)
        OR LOWER(professional.lastName) LIKE LOWER(:searchLike)
        OR LOWER(professional.specialite) LIKE LOWER(:searchLike)
        OR LOWER(professional.specialiteAutre) LIKE LOWER(:searchLike)
      )
    `, { 
      search: sanitizedSearch,
      searchLike: `%${sanitizedSearch}%`
    });
  }

  // FIXED: Updated location filter to use ST_MakePoint instead of ST_GeogFromText
  private applyLocationFilter(
    queryBuilder: SelectQueryBuilder<Professional>,
    latitude?: number,
    longitude?: number,
    maxDistance?: number
  ): void {
    if (!latitude || !longitude) {
      queryBuilder.addOrderBy('professional.createdAt', 'DESC');
      return;
    }

    const distance = Math.min(200, Math.max(1, maxDistance || 50));

    queryBuilder
      .addSelect(`
        CASE 
          WHEN professional.latitude IS NOT NULL AND professional.longitude IS NOT NULL THEN
            ST_Distance(
              ST_SetSRID(ST_MakePoint(professional.longitude, professional.latitude), 4326)::geography,
              ST_SetSRID(ST_MakePoint(:longitude, :latitude), 4326)::geography
            ) / 1000
          ELSE NULL
        END as distance
      `)
      .andWhere(`
        professional.latitude IS NOT NULL 
        AND professional.longitude IS NOT NULL
        AND ST_DWithin(
          ST_SetSRID(ST_MakePoint(professional.longitude, professional.latitude), 4326)::geography,
          ST_SetSRID(ST_MakePoint(:longitude, :latitude), 4326)::geography,
          :maxDistance * 1000
        )
      `, { latitude, longitude, maxDistance: distance })
      .addOrderBy('distance', 'ASC');
  }

  private async getSecureCount(queryBuilder: SelectQueryBuilder<Professional>): Promise<number> {
    const countQuery = queryBuilder.clone()
      .select('COUNT(DISTINCT professional.id)', 'count');
    
    (countQuery as any).expressionMap.orderBys = [];
    
    const result = await countQuery.getRawOne();
    return parseInt(result.count, 10);
  }

  private mapToSafeResponse(
    professionals: Professional[],
    latitude?: number,
    longitude?: number,
    raw?: any[]
  ): SafeProfessionalResponse[] {
    return professionals.map((professional, index) => {
      const safeData: SafeProfessionalResponse = {
        id: professional.id,
        titre: professional.titre,
        firstName: professional.firstName,
        lastName: professional.lastName,
        specialite: professional.specialite,
        specialiteAutre: professional.specialiteAutre,
        pays: professional.pays,
        ville: professional.ville,
        adresse: professional.adresse,
        codePostal: professional.codePostal,
        telephoneCabinet: professional.telephoneCabinet,
        status: professional.status,
        createdAt: professional.createdAt,
        profileImage: professional.profileImage,
        horaires: professional.horaires
      };

      if (latitude && longitude && raw && raw[index]?.distance) {
        safeData.distance = parseFloat(raw[index].distance);
      }

      return safeData;
    });
  }

  async updateProfessional(id: number, data: Partial<Professional>, userRole?: string): Promise<Professional> {
    const allowedFields = [
      'firstName', 'lastName', 'specialite', 'specialiteAutre', 
      'ville', 'adresse', 'codePostal', 'telephoneCabinet', 
      'profileImage', 'horaires'
    ];
    const sanitizedData = this.sanitizeInputData(data, allowedFields);

    await this.professionalRepository.update(id, sanitizedData);
    const professional = await this.professionalRepository.findOne({ where: { id } });
    
    if (!professional) {
      throw new BadRequestException('Professionnel non trouvé');
    }

    if (data.firstName || data.lastName || data.specialite || data.specialiteAutre || data.ville || data.adresse) {
      await this.updateSearchVector(professional);
      await this.professionalRepository.save(professional);
    }

    return professional;
  }

  private sanitizeInputData(data: Partial<Professional>, allowedFields?: string[]): Partial<Professional> {
    const sanitized: Partial<Professional> = {};

    const defaultAllowedFields = [
      'titre', 'firstName', 'lastName', 'specialite', 'specialiteAutre',
      'pays', 'ville', 'adresse', 'codePostal', 'telephoneCabinet', 
      'telephonePortable', 'latitude', 'longitude', 'profileImage', 'horaires'
    ];

    const fieldsToCheck = allowedFields || defaultAllowedFields;

    fieldsToCheck.forEach(field => {
      if (data[field] !== undefined) {
        if (typeof data[field] === 'string') {
          sanitized[field] = data[field].toString().trim().substring(0, 255);
        } else {
          sanitized[field] = data[field];
        }
      }
    });

    return sanitized;
  }

  private async updateSearchVector(professional: Professional): Promise<void> {
    const searchText = [
      professional.firstName,
      professional.lastName,
      professional.specialite,
      professional.specialiteAutre,
      professional.ville,
      professional.adresse
    ].filter(Boolean).join(' ');

    await this.professionalRepository.query(`
      UPDATE professionals 
      SET "searchVector" = to_tsvector('french', $1)
      WHERE id = $2
    `, [searchText, professional.id]);
  }

  async approveProfessional(id: number, userRole?: string): Promise<Professional> {
    if (userRole !== 'admin') {
      throw new ForbiddenException('Seuls les administrateurs peuvent valider des professionnels');
    }

    const professional = await this.professionalRepository.findOne({ 
      where: { id },
      relations: ['account']
    });
    
    if (!professional) {
      throw new BadRequestException('Professionnel non trouvé');
    }

    professional.status = 'validated';
    const savedProfessional = await this.professionalRepository.save(professional);

    if (professional.account) {
      professional.account.isActive = true;
      await this.userRepository.save(professional.account);
    }

    return savedProfessional;
  }

  // FIXED: Updated getNearbyProfessionals to use ST_MakePoint
  async getNearbyProfessionals(
    latitude: number, 
    longitude: number, 
    radius: number = 10,
    userRole?: string
  ): Promise<SafeProfessionalResponse[]> {
    if (!latitude || !longitude) {
      throw new BadRequestException('Coordonnées latitude et longitude requises');
    }

    if (latitude < -90 || latitude > 90) {
      throw new BadRequestException('Latitude invalide');
    }

    if (longitude < -180 || longitude > 180) {
      throw new BadRequestException('Longitude invalide');
    }

    const safeRadius = Math.min(50, Math.max(1, radius));

    const results = await this.professionalRepository.query(`
      SELECT 
        id, titre, "firstName", "lastName", specialite, "specialiteAutre", 
        pays, ville, adresse, "codePostal", "telephoneCabinet", status, 
        "createdAt", "profileImage", horaires,
        ST_Distance(
          ST_SetSRID(ST_MakePoint(longitude, latitude), 4326)::geography,
          ST_SetSRID(ST_MakePoint($2, $1), 4326)::geography
        ) / 1000 as distance
      FROM professionals
      WHERE status = 'validated'
        AND latitude IS NOT NULL 
        AND longitude IS NOT NULL
        AND ST_DWithin(
          ST_SetSRID(ST_MakePoint(longitude, latitude), 4326)::geography,
          ST_SetSRID(ST_MakePoint($2, $1), 4326)::geography,
          $3 * 1000
        )
      ORDER BY distance
      LIMIT 50
    `, [latitude, longitude, safeRadius]);

    return results.map(result => ({
      id: result.id,
      titre: result.titre,
      firstName: result.firstName,
      lastName: result.lastName,
      specialite: result.specialite,
      specialiteAutre: result.specialiteAutre,
      pays: result.pays,
      ville: result.ville,
      adresse: result.adresse,
      codePostal: result.codePostal,
      telephoneCabinet: result.telephoneCabinet,
      status: result.status,
      createdAt: result.createdAt,
      profileImage: result.profileImage,
      horaires: result.horaires,
      distance: parseFloat(result.distance)
    }));
  }

  async checkRateLimit(userId: number, action: string): Promise<boolean> {
    return true; // Placeholder
  }
  async getProfessionalById(id: number){
    let professional = await this.professionalRepository.findOne({
      where: { accountId: id },
      select: [
        'id', 'titre', 'firstName', 'lastName', 'specialite', 
        'specialiteAutre', 'pays', 'ville', 'adresse', 
        'codePostal', 'telephoneCabinet', 'status', 
        'createdAt', 'profileImage', 'horaires','telephonePortable'
      ],relations: ['account']
    });

    if (!professional) {
      return null;
    }
   const { account, ...rest } = professional;
  return { ...rest, email: professional.account.email }; // Remove account details for security
    
  }
   async getAllProfessionals() {
  const professionals = await this.professionalRepository.find({
    select: [
      'id', 'titre', 'firstName', 'lastName', 'specialite',
      'specialiteAutre', 'pays', 'ville', 'adresse',
      'codePostal', 'telephoneCabinet', 'status',
      'createdAt', 'profileImage', 'horaires', 'telephonePortable'
    ],
    relations: ['account'], // Include account to access email
  });

  if (!professionals || professionals.length === 0) {
    return [];
  }

  // Map over the professionals and remove account details, keeping only the email
  const sanitizedProfessionals = professionals.map((professional) => {
    const { account, ...rest } = professional;
    return { ...rest, email: account?.email }; // Include email only
  });

  return sanitizedProfessionals;
}
async rejectProfessional(id: number, reason?: string, userRole?: string): Promise<Professional> {
    // Security: Only admins can reject professionals
    if (userRole !== 'admin') {
      throw new ForbiddenException('Seuls les administrateurs peuvent rejeter des professionnels');
    }

    const professional = await this.professionalRepository.findOne({ 
      where: { id },
      relations: ['account']
    });
    
    if (!professional) {
      throw new BadRequestException('Professionnel non trouvé');
    }

    // Update status and add rejection reason
    professional.status = 'rejected';
    if (reason) {
      professional.validationNotes = reason;
    }
    
    const savedProfessional = await this.professionalRepository.save(professional);

    // Optionally deactivate the user account
    if (professional.account) {
      professional.account.isActive = false;
      await this.userRepository.save(professional.account);
    }

    return savedProfessional;
  }
  
}