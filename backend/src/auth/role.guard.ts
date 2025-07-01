import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/entities/user.entity';
import { Repository } from 'typeorm';


@Injectable()
export class RoleGuard implements CanActivate {
  constructor(
    private reflector: Reflector,

    @InjectRepository(User)
    private accountRepository: Repository<User>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Get required roles from decorator
    const requiredRoles = this.reflector.getAllAndOverride<string[]>('roles', [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user) {
      throw new ForbiddenException('User not authenticated');
    }

    // CRITICAL: Always verify against database, never trust JWT alone
    const dbUser = await this.accountRepository.findOne({
      where: { id: user.sub },
      select: ['id', 'roles', 'isActive', 'isEmailVerified']
    });

    if (!dbUser) {
      throw new ForbiddenException('User not found');
    }

    if (!dbUser.isActive) {
      throw new ForbiddenException('Account is deactivated');
    }

    if (!dbUser.isEmailVerified) {
      throw new ForbiddenException('Email not verified');
    }

    // Check if user has required role
    if (!requiredRoles.includes(dbUser.roles)) {
      throw new ForbiddenException(`Access denied. Required roles: ${requiredRoles.join(', ')}`);
    }

    // Add fresh user data to request
    request.user = { ...user, roles: dbUser.roles, isActive: dbUser.isActive };
    
    return true;
  }
}