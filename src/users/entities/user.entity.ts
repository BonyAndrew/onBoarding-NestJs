import { Entity, PrimaryGeneratedColumn, Column, BeforeInsert, ManyToMany, JoinTable, ManyToOne, JoinColumn } from 'typeorm';
import * as bcrypt from 'bcryptjs';
import { Role } from 'src/roles/entities/role.entity';

@Entity({ name: 'users' }) 
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column('text')
  name: string;

  @Column('text')
  email: string;

  @Column(
    { nullable: false }
  )
  password: string;

  @Column({ nullable: true }) 
  token: string;

  @Column({ default: false })
  isValidated: boolean;

  @Column({ nullable: true })
  resetPasswordToken: string;

  @Column({ nullable: true })
  resetPasswordTokenExpiration: Date;

  @BeforeInsert()
  async hashPassword() {
    this.password = await bcrypt.hash(this.password, 10);
  }

  @ManyToOne(() => Role, role => role.users)
  @JoinColumn({ name: 'idRole' })
  role: Role;
}
