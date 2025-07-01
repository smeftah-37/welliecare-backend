
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
} from 'typeorm';
@Entity()
export class Justificatif {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  candidatureId: number;

  @Column()
  justificatifsId: number;


  @Column({ type: 'float' })
  size: number;

  @Column()
  path: string;

}


