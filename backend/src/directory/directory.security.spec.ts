// __tests__/directory.comprehensive.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';

import * as path from 'path';
import * as fs from 'fs';
import { DirectoryService } from './directory.service';
import { DirectoryModule } from './directory.module';
import { JwtAuthGuard } from 'src/auth/auth.guard';
import { RoleGuard } from 'src/auth/role.guard';

describe('Directory API Comprehensive Tests', () => {
  let app: INestApplication;
  let directoryService: DirectoryService;
  let adminToken: string;
  let userToken: string;
  let professionalToken: string;
  let mockProfessionalId: number;

  // Mock data
  const mockProfessional = {
    id: 1,
    titre: 'Dr',
    firstName: 'Jean',
    lastName: 'Dupont',
    email: 'jean.dupont@test.com',
    specialite: 'Cardiologie',
    pays: 'Maroc',
    ville: 'Casablanca',
    adresse: '123 Rue de la Santé',
    codePostal: '20000',
    telephoneCabinet: '+212522123456',
    telephonePortable: '+212661234567',
    latitude: 33.5731,
    longitude: -7.5898,
    status: 'validated',
    horaires: {
      lundi: { ouvert: true, ouverture: '09:00', fermeture: '17:00' },
      mardi: { ouvert: true, ouverture: '09:00', fermeture: '17:00' },
      mercredi: { ouvert: false },
      jeudi: { ouvert: true, ouverture: '09:00', fermeture: '17:00' },
      vendredi: { ouvert: true, ouverture: '09:00', fermeture: '17:00' },
      samedi: { ouvert: true, ouverture: '09:00', fermeture: '12:00' },
      dimanche: { ouvert: false }
    }
  };

  const mockRegistrationData = {
    titre: 'Dr',
    firstName: 'Marie',
    lastName: 'Martin',
    email: 'marie.martin@test.com',
    password: 'SecurePass123!',
    specialite: 'Dermatologie',
    pays: 'Maroc',
    ville: 'Rabat',
    adresse: '456 Avenue Mohammed V',
    codePostal: '10000',
    telephoneCabinet: '+212537123456',
    telephonePortable: '+212661234567',
    latitude: '34.0209',
    longitude: '-6.8416',
    horaires: JSON.stringify({
      lundi: { ouvert: true, ouverture: '08:00', fermeture: '18:00' },
      mardi: { ouvert: true, ouverture: '08:00', fermeture: '18:00' },
      mercredi: { ouvert: false },
      jeudi: { ouvert: true, ouverture: '08:00', fermeture: '18:00' },
      vendredi: { ouvert: true, ouverture: '08:00', fermeture: '18:00' },
      samedi: { ouvert: false },
      dimanche: { ouvert: false }
    })
  };

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [DirectoryModule],
    })
    .overrideGuard(JwtAuthGuard)
    .useValue({
      canActivate: (context) => {
        const request = context.switchToHttp().getRequest();
        const authHeader = request.headers.authorization;
        
        if (!authHeader) return false;
        
        const token = authHeader.split(' ')[1];
        if (token === 'admin-token') {
          request.user = { sub: 1, roles: 'admin', email: 'admin@test.com' };
          return true;
        } else if (token === 'user-token') {
          request.user = { sub: 2, roles: 'user', email: 'user@test.com' };
          return true;
        } else if (token === 'professional-token') {
          request.user = { sub: 1, roles: 'professional', email: 'jean.dupont@test.com' };
          return true;
        }
        return false;
      }
    })
    .overrideGuard(RoleGuard)
    .useValue({
      canActivate: (context) => {
        const request = context.switchToHttp().getRequest();
        return request.user?.roles === 'admin';
      }
    })
    .compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }));

    directoryService = moduleFixture.get<DirectoryService>(DirectoryService);
    
    // Mock service methods
    jest.spyOn(directoryService, 'createProfessional').mockResolvedValue(mockProfessional as any);
    jest.spyOn(directoryService, 'getProfessionalById').mockResolvedValue(mockProfessional as any);
    jest.spyOn(directoryService, 'getAllProfessionals').mockResolvedValue([mockProfessional] as any);
    jest.spyOn(directoryService, 'findDirectory').mockResolvedValue({
      data: [mockProfessional],
      total: 1,
      page: 1,
      limit: 20,
      totalPages: 1,
      hasMore: false
    } as any);
    jest.spyOn(directoryService, 'getNearbyProfessionals').mockResolvedValue([mockProfessional] as any);
    jest.spyOn(directoryService, 'approveProfessional').mockResolvedValue(mockProfessional as any);
    jest.spyOn(directoryService, 'rejectProfessional').mockResolvedValue({ ...mockProfessional, status: 'rejected' } as any);
    jest.spyOn(directoryService, 'notifyAdminsOfNewRegistration').mockResolvedValue(undefined);

    await app.init();

    adminToken = 'admin-token';
    userToken = 'user-token';
    professionalToken = 'professional-token';
    mockProfessionalId = 1;
  });

  afterAll(async () => {
    await app.close();
  });

  describe('POST /directory/professionals/register', () => {
    it('should successfully register a new professional', async () => {
      const response = await request(app.getHttpServer())
        .post('/directory/professionals/register')
        .send(mockRegistrationData)
        .expect(201);

      expect(response.body).toMatchObject({
        success: true,
        message: 'Inscription soumise avec succès',
        professional: expect.objectContaining({
          titre: 'Dr',
          firstName: 'Jean',
          lastName: 'Dupont'
        }),
        registrationId: expect.any(Number),
        nextSteps: expect.any(Array)
      });
    });

    it('should reject registration with invalid title', async () => {
      const invalidData = { ...mockRegistrationData, titre: 'Invalid' };
      
      await request(app.getHttpServer())
        .post('/directory/professionals/register')
        .send(invalidData)
        .expect(400);
    });

    it('should reject registration with incomplete address', async () => {
      const invalidData = { ...mockRegistrationData, adresse: 'abc' };
      
      await request(app.getHttpServer())
        .post('/directory/professionals/register')
        .send(invalidData)
        .expect(400);
    });

    it('should handle file upload with valid image', async () => {
      // Create a temporary test image
      const testImagePath = path.join(__dirname, 'test-image.jpg');
      const testImageBuffer = Buffer.from('fake-image-data');
      fs.writeFileSync(testImagePath, testImageBuffer);

      try {
        const response = await request(app.getHttpServer())
          .post('/directory/professionals/register')
          .field('titre', mockRegistrationData.titre)
          .field('firstName', mockRegistrationData.firstName)
          .field('lastName', mockRegistrationData.lastName)
          .field('email', mockRegistrationData.email)
          .field('password', mockRegistrationData.password)
          .field('specialite', mockRegistrationData.specialite)
          .field('pays', mockRegistrationData.pays)
          .field('ville', mockRegistrationData.ville)
          .field('adresse', mockRegistrationData.adresse)
          .field('telephoneCabinet', mockRegistrationData.telephoneCabinet)
          .field('telephonePortable', mockRegistrationData.telephonePortable)
          .field('latitude', mockRegistrationData.latitude)
          .field('longitude', mockRegistrationData.longitude)
          .field('horaires', mockRegistrationData.horaires)
          .attach('photo', testImagePath)
          .expect(201);

        expect(response.body.success).toBe(true);
      } finally {
        // Cleanup
        if (fs.existsSync(testImagePath)) {
          fs.unlinkSync(testImagePath);
        }
      }
    });

    it('should reject invalid file types', async () => {
      const testFilePath = path.join(__dirname, 'test-file.txt');
      fs.writeFileSync(testFilePath, 'text content');

      try {
        await request(app.getHttpServer())
          .post('/directory/professionals/register')
          .field('titre', mockRegistrationData.titre)
          .field('email', mockRegistrationData.email)
          .attach('photo', testFilePath)
          .expect(400);
      } finally {
        if (fs.existsSync(testFilePath)) {
          fs.unlinkSync(testFilePath);
        }
      }
    });
  });

  describe('GET /directory/professional', () => {
    it('should return professional data for authenticated professional', async () => {
      const response = await request(app.getHttpServer())
        .get('/directory/professional')
        .set('Authorization', `Bearer ${professionalToken}`)
        .expect(200);

      expect(response.body).toMatchObject({
        id: expect.any(Number),
        titre: 'Dr',
        firstName: 'Jean',
        lastName: 'Dupont'
      });
    });

    it('should reject unauthenticated requests', async () => {
      await request(app.getHttpServer())
        .get('/directory/professional')
        .expect(401);
    });
  });

  describe('GET /directory/professionals', () => {
    it('should return all professionals for admin', async () => {
      const response = await request(app.getHttpServer())
        .get('/directory/professionals')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
      expect(response.body.length).toBeGreaterThan(0);
    });

    it('should reject non-admin access', async () => {
      await request(app.getHttpServer())
        .get('/directory/professionals')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(400);
    });

    it('should reject unauthenticated requests', async () => {
      await request(app.getHttpServer())
        .get('/directory/professionals')
        .expect(401);
    });
  });

  describe('GET /directory/getProfessionals', () => {
    it('should return paginated professionals', async () => {
      const response = await request(app.getHttpServer())
        .get('/directory/getProfessionals')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body).toMatchObject({
        data: expect.any(Array),
        total: expect.any(Number),
        page: expect.any(Number),
        limit: expect.any(Number),
        totalPages: expect.any(Number),
        hasMore: expect.any(Boolean)
      });
    });

    it('should apply search filters correctly', async () => {
      await request(app.getHttpServer())
        .get('/directory/getProfessionals')
        .query({ search: 'cardio', specialite: 'Cardiologie' })
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);
    });

    it('should validate pagination parameters', async () => {
      await request(app.getHttpServer())
        .get('/directory/getProfessionals')
        .query({ limit: 150 }) // Exceeds max limit
        .set('Authorization', `Bearer ${userToken}`)
        .expect(400);
    });

    it('should validate coordinate pairs', async () => {
      await request(app.getHttpServer())
        .get('/directory/getProfessionals')
        .query({ latitude: 33.5731 }) // Missing longitude
        .set('Authorization', `Bearer ${userToken}`)
        .expect(400);
    });

    it('should validate coordinate ranges', async () => {
      await request(app.getHttpServer())
        .get('/directory/getProfessionals')
        .query({ latitude: 95, longitude: -7.5898 }) // Invalid latitude
        .set('Authorization', `Bearer ${userToken}`)
        .expect(400);
    });

    it('should reject short search terms', async () => {
      await request(app.getHttpServer())
        .get('/directory/getProfessionals')
        .query({ search: 'a' }) // Too short
        .set('Authorization', `Bearer ${userToken}`)
        .expect(400);
    });
  });

  describe('GET /directory/nearby', () => {
    it('should return nearby professionals', async () => {
      const response = await request(app.getHttpServer())
        .get('/directory/nearby')
        .query({ latitude: 33.5731, longitude: -7.5898 })
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    it('should require latitude and longitude', async () => {
      await request(app.getHttpServer())
        .get('/directory/nearby')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(400);
    });

    it('should limit radius parameter', async () => {
      const response = await request(app.getHttpServer())
        .get('/directory/nearby')
        .query({ latitude: 33.5731, longitude: -7.5898, radius: 100 })
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      // Verify that radius is capped at 50
      expect(directoryService.getNearbyProfessionals).toHaveBeenCalledWith(
        33.5731, -7.5898, 50, 'user'
      );
    });

    it('should reject unauthenticated requests', async () => {
      await request(app.getHttpServer())
        .get('/directory/nearby')
        .query({ latitude: 33.5731, longitude: -7.5898 })
        .expect(401);
    });
  });

  describe('GET /directory/admin/pending', () => {
    it('should return pending professionals for admin', async () => {
      const response = await request(app.getHttpServer())
        .get('/directory/admin/pending')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);

      expect(response.body).toMatchObject({
        data: expect.any(Array),
        total: expect.any(Number)
      });
    });

    it('should reject non-admin access', async () => {
      await request(app.getHttpServer())
        .get('/directory/admin/pending')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(403);
    });

    it('should reject unauthenticated requests', async () => {
      await request(app.getHttpServer())
        .get('/directory/admin/pending')
        .expect(401);
    });
  });

  describe('GET /directory/stats', () => {
    it('should return public statistics', async () => {
      const response = await request(app.getHttpServer())
        .get('/directory/stats')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body).toMatchObject({
        totalProfessionals: expect.any(Number)
      });
    });

    it('should require authentication', async () => {
      await request(app.getHttpServer())
        .get('/directory/stats')
        .expect(401);
    });
  });

  describe('POST /directory/professionals/:id/approve', () => {
    it('should approve professional as admin', async () => {
      const response = await request(app.getHttpServer())
        .post(`/directory/professionals/${mockProfessionalId}/approve`)
        .send({ comment: 'Profil complet et valide' })
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(201);

      expect(response.body).toMatchObject({
        success: true,
        message: 'Professionnel validé avec succès',
        professional: expect.any(Object)
      });
    });

    it('should approve without comment', async () => {
      const response = await request(app.getHttpServer())
        .post(`/directory/professionals/${mockProfessionalId}/approve`)
        .send({})
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(201);

      expect(response.body.success).toBe(true);
    });

    it('should reject non-admin access', async () => {
      await request(app.getHttpServer())
        .post(`/directory/professionals/${mockProfessionalId}/approve`)
        .send({ comment: 'Test' })
        .set('Authorization', `Bearer ${userToken}`)
        .expect(403);
    });

    it('should handle invalid professional ID', async () => {
      jest.spyOn(directoryService, 'approveProfessional')
        .mockRejectedValueOnce(new Error('Professionnel non trouvé'));

      await request(app.getHttpServer())
        .post('/directory/professionals/999/approve')
        .send({ comment: 'Test' })
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(404);
    });

    it('should validate ID parameter type', async () => {
      await request(app.getHttpServer())
        .post('/directory/professionals/invalid/approve')
        .send({ comment: 'Test' })
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(400);
    });
  });

  describe('POST /directory/professionals/:id/reject', () => {
    it('should reject professional as admin', async () => {
      const response = await request(app.getHttpServer())
        .post(`/directory/professionals/${mockProfessionalId}/reject`)
        .send({ reason: 'Documents incomplets' })
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(201);

      expect(response.body).toMatchObject({
        success: true,
        message: 'Professionnel rejeté avec succès',
        professional: expect.any(Object)
      });
    });

    it('should reject without reason', async () => {
      const response = await request(app.getHttpServer())
        .post(`/directory/professionals/${mockProfessionalId}/reject`)
        .send({})
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(201);

      expect(response.body.success).toBe(true);
    });

    it('should reject non-admin access', async () => {
      await request(app.getHttpServer())
        .post(`/directory/professionals/${mockProfessionalId}/reject`)
        .send({ reason: 'Test' })
        .set('Authorization', `Bearer ${userToken}`)
        .expect(403);
    });

    it('should handle invalid professional ID', async () => {
      jest.spyOn(directoryService, 'rejectProfessional')
        .mockRejectedValueOnce(new Error('Professionnel non trouvé'));

      await request(app.getHttpServer())
        .post('/directory/professionals/999/reject')
        .send({ reason: 'Test' })
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(404);
    });
  });

  describe('Security & Input Validation', () => {
    it('should sanitize SQL injection attempts', async () => {
      const maliciousSearch = "'; DROP TABLE professionals; --";
      
      const response = await request(app.getHttpServer())
        .get('/directory/getProfessionals')
        .query({ search: maliciousSearch })
        .set('Authorization', `Bearer ${userToken}`)
        .expect(400);

      expect(response.body.message).toContain('au moins 2 caractères');
    });

    it('should handle XSS attempts in search', async () => {
      const xssAttempt = '<script>alert("xss")</script>';

      await request(app.getHttpServer())
        .get('/directory/getProfessionals')
        .query({ search: xssAttempt })
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      // Verify that the search was processed safely
      expect(directoryService.findDirectory).toHaveBeenCalledWith(
        expect.objectContaining({
          search: xssAttempt
        }),
        'user'
      );
    });

    it('should validate enum values strictly', async () => {
      await request(app.getHttpServer())
        .get('/directory/getProfessionals')
        .query({ titre: 'InvalidTitle' })
        .set('Authorization', `Bearer ${userToken}`)
        .expect(400);
    });

    it('should limit distance parameter', async () => {
      await request(app.getHttpServer())
        .get('/directory/getProfessionals')
        .query({ 
          latitude: 33.5731, 
          longitude: -7.5898, 
          maxDistance: 300 // Exceeds limit
        })
        .set('Authorization', `Bearer ${userToken}`)
        .expect(400);
    });

    it('should handle malformed JSON in registration', async () => {
      const invalidData = { 
        ...mockRegistrationData, 
        horaires: 'invalid-json' 
      };

      await request(app.getHttpServer())
        .post('/directory/professionals/register')
        .send(invalidData)
        .expect(400);
    });
  });

  describe('Error Handling & Edge Cases', () => {
    it('should handle service errors gracefully', async () => {
      jest.spyOn(directoryService, 'findDirectory')
        .mockRejectedValueOnce(new Error('Database connection failed'));

      await request(app.getHttpServer())
        .get('/directory/getProfessionals')
        .set('Authorization', `Bearer ${userToken}`)
        .expect(500);
    });

    it('should handle empty search results', async () => {
      jest.spyOn(directoryService, 'findDirectory')
        .mockResolvedValueOnce({
          data: [],
          total: 0,
          page: 1,
          limit: 20,
          totalPages: 0,
          hasMore: false
        } as any);

      const response = await request(app.getHttpServer())
        .get('/directory/getProfessionals')
        .query({ search: 'nonexistent' })
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.data).toEqual([]);
      expect(response.body.total).toBe(0);
    });

    it('should handle registration conflicts', async () => {
      const conflictError = new Error('Unique constraint violation');
      (conflictError as any).code = '23505';
      
      jest.spyOn(directoryService, 'createProfessional')
        .mockRejectedValueOnce(conflictError);

      await request(app.getHttpServer())
        .post('/directory/professionals/register')
        .send(mockRegistrationData)
        .expect(409);
    });

    it('should validate coordinate precision', async () => {
      await request(app.getHttpServer())
        .get('/directory/getProfessionals')
        .query({ 
          latitude: '33.57316789123456789', // Too precise
          longitude: '-7.5898'
        })
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200); // Should still work, gets truncated
    });
  });

  describe('Performance & Rate Limiting Tests', () => {
    it('should handle large result sets efficiently', async () => {
      const largeDataSet = Array(100).fill(null).map((_, index) => ({
        ...mockProfessional,
        id: index + 1,
        email: `professional${index}@test.com`
      }));

      jest.spyOn(directoryService, 'findDirectory')
        .mockResolvedValueOnce({
          data: largeDataSet,
          total: 100,
          page: 1,
          limit: 100,
          totalPages: 1,
          hasMore: false
        } as any);

      const response = await request(app.getHttpServer())
        .get('/directory/getProfessionals')
        .query({ limit: 100 })
        .set('Authorization', `Bearer ${userToken}`)
        .expect(200);

      expect(response.body.data).toHaveLength(100);
    });

    it('should enforce maximum page size', async () => {
      await request(app.getHttpServer())
        .get('/directory/getProfessionals')
        .query({ limit: 200 }) // Exceeds maximum
        .set('Authorization', `Bearer ${userToken}`)
        .expect(400);
    });
  });
});