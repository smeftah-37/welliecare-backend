import { ApiProperty } from "@nestjs/swagger";
import { Transform, Type } from "class-transformer";
import { IsArray, IsBoolean, IsEmail, IsEnum, IsNotEmpty, IsNumber, IsOptional, IsString, IsUrl, Length, Matches, Max, MaxLength, Min, MinLength, ValidateNested } from "class-validator";
import { UserRole } from "src/entities/user.entity";
const VALID_ROLES= ['user' , 'pro' , 'admin'] as const;

const sanitizeString = (value: string): string => {
  if (typeof value !== 'string') return '';

  return value
    .replace(/\0/g, '') // Remove NULL bytes
    .replace(/[\x00-\x1F\x7F]/g, '') // Remove control characters
    .replace(/[^a-zA-Z0-9À-ÿ\s'°.,-<>]/g, '') // Allow French characters, numbers, spaces, punctuation, and < >
    .trim()
    .substring(0, 1000); // Limit length
};
const sanitizeEmail = (value: string): string => {
  if (typeof value !== 'string') return '';
  return value
    .toLowerCase()
    .replace(/[^\w@.-]/g, '') // Only allow word chars, @, ., -
    .trim()
    .substring(0, 254); // RFC 5321 limit
};

const sanitizeNumeric = (value: any): number | undefined => {
  if (value === null || value === undefined) {
    return undefined; // Return undefined for null or undefined
  }

  if (typeof value === 'object' && 'toNumber' in value) {
    value = value.toNumber; // Extract the numeric value from objects like { toNumber: 10000 }
  }

  const num = Number(value); // Convert to number
  if (isNaN(num)) {
    return undefined; // Return undefined for invalid numbers
  }

  return Math.floor(Math.abs(num)); // Return the absolute value as an integer
};


// Enhanced password validation regex
const STRONG_PASSWORD_REGEX = /^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,}$/;
export class LoginDto {
  @ApiProperty({
    description: 'Adresse email de l\'utilisateur',
    example: 'utilisateur@exemple.com',
    format: 'email',
    maxLength: 254,
    required: true
  })
  @Transform(({ value }) => sanitizeEmail(value))
  @IsEmail({}, { message: 'Format d\'email incorrect' })
  @IsNotEmpty({ message: 'L\'email est requis' })
  @MaxLength(254, { message: 'Email trop long' })
  email: string;

  @ApiProperty({
    description: 'Mot de passe de l\'utilisateur',
    example: 'monMotDePasseSecurise123!',
    minLength: 8,
    maxLength: 128,
    required: true
  })
  @IsString({ message: 'Le mot de passe doit être une chaîne' })
  @IsNotEmpty({ message: 'Le mot de passe est requis' })
  @MinLength(8, { message: 'Le mot de passe est trop court' })
  @MaxLength(128, { message: 'Le mot de passe est trop long' })
  password: string;
}

export class ForgotPasswordDto {
  @ApiProperty({
    description: 'Adresse email pour envoyer le code de réinitialisation',
    example: 'utilisateur@exemple.com',
    format: 'email',
    maxLength: 254,
    required: true
  })
  @Transform(({ value }) => sanitizeEmail(value))
  @IsEmail({}, { message: 'Veuillez entrer un email valide' })
  @MaxLength(254, { message: 'Email trop long' })
  email: string;
}

export class ResetPasswordDto {
  @Transform(({ value }) => sanitizeEmail(value))
  @IsEmail({}, { message: 'Format d\'email incorrect' })
  @MaxLength(254, { message: 'Email trop long' })
  email: string;

  @IsString({ message: 'Le code doit être une chaîne' })
  @Matches(/^\d+$/, { message: 'Le code doit être numérique' })
  @Length(6, 6, { message: 'Le code doit contenir 6 caractères' })
  code: string;


  @IsString({ message: 'Le mot de passe doit être une chaîne' })
  @MinLength(8, { message: 'Le mot de passe est trop court' })
  @MaxLength(128, { message: 'Le mot de passe est trop long' })
  // @Matches(STRONG_PASSWORD_REGEX, {
  //   message: 'Le mot de passe doit contenir au moins une majuscule, une minuscule, un chiffre et un caractère spécial'
  // })
  newPassword: string;
}

// Additional security middleware/decorator that can be applied at the controller level
export interface SecurityValidationOptions {
  enableRateLimit?: boolean;
  enableCSRFProtection?: boolean;
  enableInputSanitization?: boolean;
  maxPayloadSize?: number;
  allowedOrigins?: string[];
}

// Custom validation decorator for additional security checks
export function SecureValidation(options: SecurityValidationOptions = {}) {
  return function (target: any, propertyName: string, descriptor: PropertyDescriptor) {
    const method = descriptor.value;
    descriptor.value = function (...args: any[]) {
      // Add additional security validations here
      // This would be implemented in your actual application
      return method.apply(this, args);
    };
  };
}

// Rate limiting configurations (to be used with express-rate-limit)
export const RATE_LIMIT_CONFIG = {
  LOGIN: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: 'Veuillez essayer plus tard'
  },
  REGISTER: {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 registrations per hour
    message: 'Veuillez essayer plus tard'
  },
  FORGOT_PASSWORD: {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 attempts per hour
    message: 'Veuillez essayer plus tard'
  },
  GENERAL: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests per window
    message: 'Veuillez essayer plus tard'
  }
};

// Security headers configuration
export const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';",
  'Referrer-Policy': 'strict-origin-when-cross-origin'
};

// Input validation patterns for common fields
export const VALIDATION_PATTERNS = {
  CIN: /^[A-Z]{1,2}[0-9]{1,8}$/,
  PHONE_MA: /^(\+212|0)[5-7][0-9]{8}$/,
  MASSAR_CODE: /^[A-Z][0-9]{9}$/,
  POSTAL_CODE_MA: /^[0-9]{5}$/,
  ARABIC_TEXT: /^[\u0600-\u06FF\s]+$/,
  LATIN_NAME: /^[a-zA-ZÀ-ÿ\s'-]+$/,
  ALPHANUMERIC: /^[a-zA-Z0-9]+$/,
  SECURE_TOKEN: /^[a-zA-Z0-9+/=._-]+$/
};

// File upload security configuration
export const FILE_UPLOAD_CONFIG = {
  MAX_FILE_SIZE: 5 * 1024 * 1024, // 5MB
  ALLOWED_MIME_TYPES: [
    'application/pdf',
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  ],
  ALLOWED_EXTENSIONS: ['.pdf'],
  SCAN_FOR_MALWARE: true,
  QUARANTINE_SUSPICIOUS: true
};

// Database query security helpers
export const DB_SECURITY = {
  // Escape special characters to prevent SQL injection
  escapeString: (str: string): string => {
    if (typeof str !== 'string') return '';
    return str.replace(/[\0\x08\x09\x1a\n\r"'\\\%]/g, (char) => {
      switch (char) {
        case '\0': return '\\0';
        case '\x08': return '\\b';
        case '\x09': return '\\t';
        case '\x1a': return '\\z';
        case '\n': return '\\n';
        case '\r': return '\\r';
        case '"':
        case "'":
        case '\\':
        case '%': return '\\' + char;
        default: return char;
      }
    });
  },
  
  // Validate UUIDs to prevent injection through ID parameters
  isValidUUID: (uuid: string): boolean => {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
  },
  
  // Validate numeric IDs
  isValidId: (id: any): boolean => {
    const numId = Number(id);
    return !isNaN(numId) && numId > 0 && numId <= 2147483647 && Number.isInteger(numId);
  }
};

// Session security configuration
export const SESSION_CONFIG = {
  secret: process.env.SESSION_SECRET || 'your-super-secure-secret-key-change-this',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    httpOnly: true, // Prevent XSS
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'strict' as const // CSRF protection
  },
  name: 'sessionId' // Don't use default session name
};

// CORS security configuration
export const CORS_CONFIG = {
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['X-Total-Count']
};

export class RefreshTokenDto {
  @IsString({ message: 'Le token doit être une chaîne' })
  @IsNotEmpty({ message: 'Le token de rafraîchissement est requis' })
  @MaxLength(512, { message: 'Token trop long' })
  @Matches(/^[A-Za-z0-9+/=._-]+$/, { message: 'Format de token invalide' })
  refresh_token: string;
}

export class RegisterDto {
  @ApiProperty({
    description: 'Adresse email pour l\'inscription',
    example: 'nouvelutilisateur@exemple.com',
    format: 'email',
    maxLength: 254,
    required: true
  })
  @Transform(({ value }) => sanitizeEmail(value))
  @IsEmail({}, { message: 'Format d\'email invalide' })
  @IsNotEmpty({ message: 'L\'email est requis' })
  @MaxLength(254, { message: 'Email trop long' })
  email: string;

  @ApiProperty({
    description: 'Mot de passe pour le nouveau compte',
    example: 'motDePasseSecurise123!',
    minLength: 8,
    maxLength: 128,
    required: true
  })
  @IsString({ message: 'Le mot de passe doit être une chaîne' })
  @MinLength(8, { message: 'Le mot de passe est trop court' })
  @MaxLength(128, { message: 'Le mot de passe est trop long' })
  password: string;
}

export class SendVerificationDto {
  @ApiProperty({
    description: 'Adresse email pour envoyer le code de vérification',
    example: 'utilisateur@exemple.com',
    format: 'email',
    maxLength: 254,
    required: true
  })
  @Transform(({ value }) => sanitizeEmail(value))
  @IsEmail({}, { message: 'Format d\'email invalide' })
  @IsNotEmpty({ message: 'L\'email est requis' })
  @MaxLength(254, { message: 'Email trop long' })
  email: string;
}
export class VerifyCodeDto {
  @Transform(({ value }) => sanitizeEmail(value))
  @IsEmail({}, { message: 'Format d\'email invalide' })
  @IsNotEmpty({ message: 'L\'email est requis' })
  @MaxLength(254, { message: 'Email trop long' })
  email: string;

  @IsString({ message: 'Le code doit être une chaîne' })
  @Matches(/^\d+$/, { message: 'Le code doit être un nombre' })
  @Length(6, 6, { message: 'Le code doit contenir 6 caractères' })
  code: string;
  @IsOptional()
  @IsString({ message: 'Le mot de passe doit être une chaîne' })
  @MinLength(8, { message: 'Le mot de passe est trop court' })
  @MaxLength(128, { message: 'Le mot de passe est trop long' })
  password?: string;

  @Transform(({ value }) => sanitizeString(value))
  @IsEnum(VALID_ROLES, { message: 'roles invalid' })
  roles: UserRole;
}

export enum Title {
  DR = 'Dr',
  PR = 'Pr',
  M = 'M.',
  MME = 'Mme'
}

export enum ValidationStatus {
  PENDING = 'pending',
  VALIDATED = 'validated',
  REJECTED = 'rejected'
}

export class DayScheduleDto implements DaySchedule {
  @IsBoolean({ message: 'Le statut d\'ouverture doit être un booléen' })
  @Transform(({ value }) => {
    if (typeof value === 'string') {
      return value === 'true';
    }
    return value;
  })
  ouvert: boolean;

  @IsOptional()
  @IsString({ message: 'L\'heure d\'ouverture doit être une chaîne' })
  @Matches(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/, { 
    message: 'Format d\'heure invalide (HH:MM)' 
  })
  ouverture?: string;

  @IsOptional()
  @IsString({ message: 'L\'heure de fermeture doit être une chaîne' })
  @Matches(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/, { 
    message: 'Format d\'heure invalide (HH:MM)' 
  })
  fermeture?: string;
}

// Define the interface first
export interface WeeklySchedule {
  lundi?: DaySchedule;
  mardi?: DaySchedule;
  mercredi?: DaySchedule;
  jeudi?: DaySchedule;
  vendredi?: DaySchedule;
  samedi?: DaySchedule;
  dimanche?: DaySchedule;
}

export interface DaySchedule {
  ouvert: boolean;
  ouverture?: string;
  fermeture?: string;
}

export class WeeklyScheduleDto implements WeeklySchedule {
  @IsOptional()
  @ValidateNested()
  @Type(() => DayScheduleDto)
  lundi?: DayScheduleDto;

  @IsOptional()
  @ValidateNested()
  @Type(() => DayScheduleDto)
  mardi?: DayScheduleDto;

  @IsOptional()
  @ValidateNested()
  @Type(() => DayScheduleDto)
  mercredi?: DayScheduleDto;

  @IsOptional()
  @ValidateNested()
  @Type(() => DayScheduleDto)
  jeudi?: DayScheduleDto;

  @IsOptional()
  @ValidateNested()
  @Type(() => DayScheduleDto)
  vendredi?: DayScheduleDto;

  @IsOptional()
  @ValidateNested()
  @Type(() => DayScheduleDto)
  samedi?: DayScheduleDto;

  @IsOptional()
  @ValidateNested()
  @Type(() => DayScheduleDto)
  dimanche?: DayScheduleDto;
}

export class ProfessionalRegistrationDto {
  @Transform(({ value }) => sanitizeEmail(value))
  @IsEmail({}, { message: 'Format d\'email invalide' })
  @IsNotEmpty({ message: 'L\'email est requis' })
  @MaxLength(254, { message: 'Email trop long' })
  email: string;

  @IsString({ message: 'Le mot de passe doit être une chaîne' })
  @MinLength(8, { message: 'Le mot de passe est trop court' })
  @MaxLength(128, { message: 'Le mot de passe est trop long' })
  password: string;

  @IsString({ message: 'La confirmation du mot de passe doit être une chaîne' })
  @IsNotEmpty({ message: 'La confirmation du mot de passe est requise' })
  confirmPassword: string;

  @IsEnum(Title, { message: 'Titre invalide (Dr, Pr, M., ou Mme)' })
  titre: Title;

  @Transform(({ value }) => sanitizeString(value))
  @IsString({ message: 'Le prénom doit être une chaîne' })
  @Length(2, 50, { message: 'Le prénom doit contenir entre 2 et 50 caractères' })
  @Matches(/^[a-zA-ZÀ-ÿ\s'-]+$/, { message: 'Le prénom contient des caractères invalides' })
  firstName: string;

  @Transform(({ value }) => sanitizeString(value))
  @IsString({ message: 'Le nom doit être une chaîne' })
  @Length(2, 50, { message: 'Le nom doit contenir entre 2 et 50 caractères' })
  @Matches(/^[a-zA-ZÀ-ÿ\s'-]+$/, { message: 'Le nom contient des caractères invalides' })
  lastName: string;

  @Transform(({ value }) => sanitizeString(value))
  @IsString({ message: 'La spécialité doit être une chaîne' })
  @Length(2, 100, { message: 'La spécialité doit contenir entre 2 et 100 caractères' })
  specialite: string;

  @IsOptional()
  @Transform(({ value }) => sanitizeString(value))
  @IsString({ message: 'La spécialité autre doit être une chaîne' })
  @MaxLength(100, { message: 'La spécialité autre ne peut dépasser 100 caractères' })
  specialiteAutre?: string;

  @Transform(({ value }) => sanitizeString(value))
  @IsString({ message: 'Le pays doit être une chaîne' })
  @Length(2, 50, { message: 'Le pays doit contenir entre 2 et 50 caractères' })
  pays: string;

  @Transform(({ value }) => sanitizeString(value))
  @IsString({ message: 'La ville doit être une chaîne' })
  @Length(2, 50, { message: 'La ville doit contenir entre 2 et 50 caractères' })
  ville: string;

  @Transform(({ value }) => sanitizeString(value))
  @IsString({ message: 'L\'adresse doit être une chaîne' })
  @Length(5, 200, { message: 'L\'adresse doit contenir entre 5 et 200 caractères' })
  adresse: string;

  @IsOptional()
  @Transform(({ value }) => sanitizeString(value))
  @IsString({ message: 'Le code postal doit être une chaîne' })
  @Matches(/^[0-9]{5}$/, { message: 'Le code postal doit contenir 5 chiffres' })
  codePostal?: string;

  @Transform(({ value }) => sanitizeString(value))
  @IsString({ message: 'Le téléphone du cabinet doit être une chaîne' })
  @Matches(/^(\+212|0)[5-7][0-9]{8}$/, {
    message: 'Format de téléphone marocain invalide'
  })
  telephoneCabinet: string;

  @Transform(({ value }) => sanitizeString(value))
  @IsString({ message: 'Le téléphone portable doit être une chaîne' })
  @Matches(/^(\+212|0)[5-7][0-9]{8}$/, {
    message: 'Format de téléphone marocain invalide'
  })
  telephonePortable: string;

  // FIXED: Proper number transformation for coordinates
  @IsOptional()
  @Transform(({ value }) => {
    if (typeof value === 'string') {
      const num = parseFloat(value);
      return isNaN(num) ? undefined : num;
    }
    return value;
  })
  @IsNumber({}, { message: 'La latitude doit être un nombre' })
  @Min(-90, { message: 'Latitude invalide' })
  @Max(90, { message: 'Latitude invalide' })
  latitude?: number;

  @IsOptional()
  @Transform(({ value }) => {
    if (typeof value === 'string') {
      const num = parseFloat(value);
      return isNaN(num) ? undefined : num;
    }
    return value;
  })
  @IsNumber({}, { message: 'La longitude doit être un nombre' })
  @Min(-180, { message: 'Longitude invalide' })
  @Max(180, { message: 'Longitude invalide' })
  longitude?: number;

  @IsOptional()
  @IsUrl({}, { message: 'URL de l\'image invalide' })
  @MaxLength(500, { message: 'URL de l\'image trop longue' })
  profileImage?: string;

  // FIXED: Proper JSON string transformation for horaires
  @IsOptional()
  @Transform(({ value }) => {
    if (typeof value === 'string') {
      try {
        return JSON.parse(value);
      } catch (error) {
        return value; // Let validation handle the error
      }
    }
    return value;
  })
  @ValidateNested()
  @Type(() => WeeklyScheduleDto)
  horaires?: WeeklyScheduleDto;

  @IsOptional()
  photo?: any; // Handle file upload separately in your controller
}


// DTO for updating professional profile
// export class UpdateProfessionalDto {
//   @IsOptional()
//   @Transform(({ value }) => sanitizeString(value))
//   @IsString({ message: 'Le prénom doit être une chaîne' })
//   @Length(2, 50, { message: 'Le prénom doit contenir entre 2 et 50 caractères' })
//   firstName?: string;

//   @IsOptional()
//   @Transform(({ value }) => sanitizeString(value))
//   @IsString({ message: 'Le nom doit être une chaîne' })
//   @Length(2, 50, { message: 'Le nom doit contenir entre 2 et 50 caractères' })
//   lastName?: string;

//   @IsOptional()
//   @Transform(({ value }) => sanitizeString(value))
//   @IsString({ message: 'La spécialité doit être une chaîne' })
//   @Length(2, 100, { message: 'La spécialité doit contenir entre 2 et 100 caractères' })
//   specialite?: string;

//   @IsOptional()
//   @Transform(({ value }) => sanitizeString(value))
//   @IsString({ message: 'Le pays doit être une chaîne' })
//   pays?: string;

//   @IsOptional()
//   @Transform(({ value }) => sanitizeString(value))
//   @IsString({ message: 'La ville doit être une chaîne' })
//   ville?: string;

//   @IsOptional()
//   @Transform(({ value }) => sanitizeString(value))
//   @IsString({ message: 'L\'adresse doit être une chaîne' })
//   addresse?: string;

//   @IsOptional()
//   @Transform(({ value }) => sanitizeString(value))
//   @IsString({ message: 'Le téléphone du cabinet doit être une chaîne' })
//   @Matches(/^(\+212|0)[5-7][0-9]{8}$/, { 
//     message: 'Format de téléphone marocain invalide' 
//   })
//   telephoneCabinet?: string;

//   @IsOptional()
//   @Transform(({ value }) => sanitizeString(value))
//   @IsString({ message: 'Le téléphone portable doit être une chaîne' })
//   @Matches(/^(\+212|0)[5-7][0-9]{8}$/, { 
//     message: 'Format de téléphone marocain invalide' 
//   })
//   telephonePortable?: string;

//   @IsOptional()
//   @IsNumber({}, { message: 'La latitude doit être un nombre' })
//   latitude?: number;

//   @IsOptional()
//   @IsNumber({}, { message: 'La longitude doit être un nombre' })
//   longitude?: number;

//   @IsOptional()
//   @IsUrl({}, { message: 'URL de l\'image invalide' })
//   profileImage?: string;

//   @IsOptional()
//   @IsArray({ message: 'Les horaires doivent être un tableau' })
//   @ValidateNested({ each: true })
//   @Type(() => DailyScheduleDto)
//   schedule?: DailyScheduleDto[];
// }

// DTO for professional search
export class SearchProfessionalDto {
  @IsOptional()
  @Transform(({ value }) => sanitizeString(value))
  @IsString({ message: 'Le terme de recherche doit être une chaîne' })
  @MaxLength(100, { message: 'Terme de recherche trop long' })
  searchTerm?: string;

  @IsOptional()
  @Transform(({ value }) => sanitizeString(value))
  @IsString({ message: 'La spécialité doit être une chaîne' })
  specialite?: string;

  @IsOptional()
  @Transform(({ value }) => sanitizeString(value))
  @IsString({ message: 'La ville doit être une chaîne' })
  ville?: string;

  @IsOptional()
  @IsNumber({}, { message: 'La latitude doit être un nombre' })
  latitude?: number;

  @IsOptional()
  @IsNumber({}, { message: 'La longitude doit être un nombre' })
  longitude?: number;

  @IsOptional()
  @IsNumber({}, { message: 'Le rayon doit être un nombre' })
  @Min(1, { message: 'Le rayon minimum est de 1 km' })
  @Max(100, { message: 'Le rayon maximum est de 100 km' })
  radius?: number; // in kilometers

  @IsOptional()
  @IsNumber({}, { message: 'La page doit être un nombre' })
  @Min(1, { message: 'La page minimum est 1' })
  page?: number;

  @IsOptional()
  @IsNumber({}, { message: 'La limite doit être un nombre' })
  @Min(1, { message: 'La limite minimum est 1' })
  @Max(50, { message: 'La limite maximum est 50' })
  limit?: number;
}

// DTO for professional validation by admin
export class ValidateProfessionalDto {
  @IsEnum(ValidationStatus, { message: 'Statut de validation invalide' })
  status: ValidationStatus;

  @IsOptional()
  @Transform(({ value }) => sanitizeString(value))
  @IsString({ message: 'Les notes doivent être une chaîne' })
  @MaxLength(500, { message: 'Notes trop longues (max 500 caractères)' })
  validationNotes?: string;
}
export class AuthResponseDto {
  @ApiProperty({
    description: 'Token d\'accès JWT',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
  })
  access_token: string;

  @ApiProperty({
    description: 'Informations de l\'utilisateur',
    type: 'object',
    properties: {
      id: { type: 'string', example: 'uuid-ici' },
      email: { type: 'string', example: 'utilisateur@exemple.com' },
      roles: { type: 'string', example: 'etudiant' },
      isActive: { type: 'boolean', example: true }
    }
  })
  user: {
    id: string;
    email: string;
    roles: string;
    isActive: boolean;
  };

  @ApiProperty({
    description: 'Message de succès',
    example: 'Connexion réussie'
  })
  message: string;
}

export class ErrorResponseDto {
  @ApiProperty({
    description: 'Code de statut HTTP',
    example: 400
  })
  statusCode: number;

  @ApiProperty({
    description: 'Message d\'erreur ou tableau d\'erreurs de validation',
    oneOf: [
      { type: 'string', example: 'Identifiants invalides' },
      { type: 'array', items: { type: 'string' }, example: ['L\'email est requis', 'Le mot de passe est trop court'] }
    ]
  })
  message: string | string[];

  @ApiProperty({
    description: 'Type d\'erreur',
    example: 'Mauvaise requête'
  })
  error: string;
}
// Response DTOs
// export class ProfessionalResponseDto {
//   id: number;
//   titre: Title;
//   firstName: string;
//   lastName: string;
//   email: string;
//   specialite: string;
//   pays: string;
//   ville: string;
//   addresse: string;
//   telephoneCabinet: string;
//   telephonePortable: string;
//   latitude?: number;
//   longitude?: number;
//   profileImage?: string;
//   status: ValidationStatus;
//   schedule?: DailyScheduleDto[];
//   distance?: number;
//   createdAt: Date;
//   updatedAt: Date;
// }

// export class ProfessionalListResponseDto {
//   professionals: ProfessionalResponseDto[];
//   total: number;
//   page: number;
//   limit: number;
//   totalPages: number;
// }

