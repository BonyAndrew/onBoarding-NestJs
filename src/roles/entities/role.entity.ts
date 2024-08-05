import { Permission } from "src/permissions/entities/permission.entity";
import { User } from "src/users/entities/user.entity";
import { Column, Entity, JoinTable, ManyToMany, OneToMany, PrimaryColumn, PrimaryGeneratedColumn } from "typeorm";

@Entity({ name: 'roles' })
export class Role {
    @PrimaryGeneratedColumn()
    id: number;

    @Column('text')
    name: string;

    @OneToMany(() => User, user => user.role)
    users: User[];

    @ManyToMany(() => Permission)
    @JoinTable({
        name: 'role_permissions',
        joinColumn: { name: 'idRole', referencedColumnName: 'id' },
        inverseJoinColumn: { name: 'idPermission', referencedColumnName: 'id' },
    })
    permissions?: Permission[];
}
