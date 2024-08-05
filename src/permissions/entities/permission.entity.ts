import { Role } from "src/roles/entities/role.entity";
import { Column, Entity, JoinTable, ManyToMany, PrimaryColumn, PrimaryGeneratedColumn } from "typeorm";

@Entity({ name: 'permissions' })
export class Permission {
    @PrimaryGeneratedColumn()
    id: number;

    @Column('text')
    name: string; 

    @ManyToMany(() => Role, role => role.permissions)
    roles: Role[];
}