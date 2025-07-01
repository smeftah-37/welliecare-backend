import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';


export enum UserRole {
  USER = 'user',
  PRO = 'pro',
  ADMIN = 'admin',
}

@Entity('users') // Table name
export class User {
  @PrimaryGeneratedColumn() // Auto-incremented number as Primary Key
  id: number;

  @Column({ unique: true })
  email: string;

  @Column({nullable: true})
  password: string; // Store hashed password

  @Column({ type: 'enum', enum: UserRole, default: UserRole.USER })
  roles: UserRole;


  @Column({ default: true })
  isActive: boolean;

  @Column({ default: false })
  isEmailVerified: boolean;

  @Column({ type: 'timestamp', nullable: true })
  lastLoginAt: Date | null;

  @Column({ type: 'timestamp', nullable: true })
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
  @Column({nullable: true})
  registrationIp: string;
}
