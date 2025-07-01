import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as argon2 from 'argon2';
import { User, UserRole } from '../entities/user.entity'; // Adjust path as needed

@Injectable()
export class UserSeederService {
  private readonly logger = new Logger(UserSeederService.name);

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async onModuleInit() {
    await this.seedUsers();
  }

  async seedUsers(): Promise<void> {
    const users = [
      {
        email: process.env.ADMIN_EMAIL || 'admin@example.com',
        password: process.env.ADMIN_PASSWORD || 'AdminPass123!',
        roles: UserRole.ADMIN,
        isActive: true,
        isEmailVerified: true,
      },
      {
        email: process.env.PRO_EMAIL || 'pro@example.com', 
        password: process.env.PRO_PASSWORD || 'ProPass123!',
        roles: UserRole.PRO,
        isActive: true,
        isEmailVerified: true,
      },
      {
        email: process.env.USER_EMAIL || 'user@example.com',
        password: process.env.USER_PASSWORD || 'UserPass123!',
        roles: UserRole.USER,
        isActive: true,
        isEmailVerified: true,
      },
      // Add more test accounts as needed
      
    ];

    for (const userData of users) {
      if (!userData.password || userData.password.trim() === '') {
        throw new Error(
          `Password not provided for ${userData.email}. Please set the corresponding environment variable.`,
        );
      }

      // Validate password strength
      if (!this.validatePassword(userData.password)) {
        throw new Error(
          `Password for ${userData.email} is too weak. Must be at least 8 characters with uppercase, lowercase, numbers, and special characters.`,
        );
      }

      try {
        const existingUser = await this.userRepository.findOne({
          where: { email: userData.email },
        });

        if (!existingUser) {
          // Hash password with argon2
          const hashedPassword = await argon2.hash(userData.password, {
            type: argon2.argon2id,
            memoryCost: 19456,
            timeCost: 2,
            parallelism: 1,
          });

          const newUser = this.userRepository.create({
            email: userData.email,
            password: hashedPassword,
            roles: userData.roles,
            isActive: userData.isActive,
            isEmailVerified: userData.isEmailVerified,
            lastLoginAt: null,
            createdAt: new Date(),
            registrationIp: '127.0.0.1', // Default for seeded accounts
          });

          const savedUser = await this.userRepository.save(newUser);
          
          this.logger.log(`✓ User created successfully for: ${userData.email} (Role: ${userData.roles})`);
          
          // Log credentials for testing (remove in production)
          this.logger.warn(`
🔐 TEST ACCOUNT CREDENTIALS
Email: ${userData.email}
Password: ${userData.password}
Role: ${userData.roles}
===============================================`);
          
        } else {
          this.logger.log(`ℹ User already exists for: ${userData.email}`);
        }
      } catch (error) {
        this.logger.error(
          `✗ Failed to create user for ${userData.email}: ${error.message}`,
        );
      }
    }

    this.logger.log('User seeding completed.');
  }

  private validatePassword(password: string): boolean {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>_\-]/.test(password);

    return (
      password.length >= minLength &&
      hasUpperCase &&
      hasLowerCase &&
      hasNumbers &&
      hasSpecialChar
    );
  }
}