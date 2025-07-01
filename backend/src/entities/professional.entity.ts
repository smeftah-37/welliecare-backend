import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  OneToOne,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';
import { User } from './user.entity';

export type Title = 'Dr' | 'Pr' | 'M.' | 'Mme';

// Updated interface to match frontend data structure
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
  ouverture?: string; // HH:MM format
  fermeture?: string; // HH:MM format
}

@Entity('professionals')
export class Professional {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'enum', enum: ['Dr', 'Pr', 'M.', 'Mme'] })
  titre: Title;

  @Column()
  firstName: string;

  @Column()
  lastName: string;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column()
  specialite: string;

  // Add specialiteAutre field
  @Column({ nullable: true })
  specialiteAutre?: string;

  @Column()
  pays: string;

  @Column()
  ville: string;

  // Fix typo: should be 'adresse' not 'addresse'
  @Column()
  adresse: string;

  // Add codePostal field
  @Column({ nullable: true })
  codePostal?: string;

  @Column()
  telephoneCabinet: string;

  @Column()
  telephonePortable: string;

  // Optional profile image
  @Column({ nullable: true })
  profileImage?: string;

  // Updated schedule to match frontend structure
  @Column({
    type: 'json',
    nullable: true,
    comment: 'Weekly schedule for the professional'
  })
  horaires?: WeeklySchedule;

  // One-to-one relation to User account
  @OneToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'accountId' })
  account: User;

  @Column()
  accountId: number;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // FIXED: Remove the location field entirely if not needed, or keep it simple
  // Option 1: Remove location field completely
  // @Column({
  //   type: 'geometry',
  //   spatialFeatureType: 'Point',
  //   srid: 4326,
  //   nullable: true
  // })
  // @Index({ spatial: true })
  // location: string;

  @Column({ type: 'decimal', precision: 10, scale: 8, nullable: true })
  latitude: number;

  @Column({ type: 'decimal', precision: 11, scale: 8, nullable: true })
  longitude: number;

  @Column({
    type: 'enum',
    enum: ['pending', 'validated', 'rejected'],
    default: 'pending'
  })
  status: string;

  @Column({
    type: 'text',
    nullable: true,
    comment: 'Admin notes for validation/rejection'
  })
  validationNotes?: string;

  @Column({
    type: 'tsvector',
    nullable: true,
    select: false
  })
  @Index({ fulltext: true })
  searchVector: string;

  distance?: number;

  // Updated helper methods
  getScheduleForDay(day: keyof WeeklySchedule): DaySchedule | undefined {
    return this.horaires?.[day];
  }

  isOpenOnDay(day: keyof WeeklySchedule): boolean {
    const daySchedule = this.getScheduleForDay(day);
    return daySchedule?.ouvert === true;
  }

  getWorkingDays(): string[] {
    if (!this.horaires) return [];
    return Object.entries(this.horaires)
      .filter(([_, schedule]) => schedule?.ouvert === true)
      .map(([day, _]) => day);
  }

  // REMOVED: This method causes the PostGIS error
  // updateLocationFromCoordinates(): void {
  //   if (this.latitude && this.longitude) {
  //     this.location = `POINT(${this.longitude} ${this.latitude})`;
  //   }
  // }

  getDisplayName(): string {
    return `${this.titre} ${this.firstName} ${this.lastName}`;
  }

  getFullAddress(): string {
    const parts = [this.adresse, this.ville, this.pays].filter(Boolean);
    if (this.codePostal) {
      parts.splice(-1, 0, this.codePostal);
    }
    return parts.join(', ');
  }

  isProfileComplete(): boolean {
    return !!(
      this.firstName &&
      this.lastName &&
      this.email &&
      this.specialite &&
      this.pays &&
      this.ville &&
      this.adresse &&
      this.telephoneCabinet &&
      this.telephonePortable
    );
  }
}