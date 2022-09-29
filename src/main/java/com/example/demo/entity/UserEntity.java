package com.example.demo.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.Set;

@Entity
@Table(name = "users")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserEntity {
    @Id
    private String username;
    @Column
    private String password;
    @Column
    private boolean accountNonLocked;
    @OneToMany(mappedBy = "user")
    private Set<RoleEntity> roles;
}
