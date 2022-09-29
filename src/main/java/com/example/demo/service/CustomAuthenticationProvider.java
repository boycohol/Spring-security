package com.example.demo.service;

import com.example.demo.entity.RoleEntity;
import com.example.demo.entity.UserEntity;
import com.example.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private UserRepository userRepository;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        System.out.println("User: " + username + "\n" + "Password: " + password);
        Optional<UserEntity>optionalUser=userRepository.findByUsername(username);
        if(!optionalUser.isPresent()){
            throw new UsernameNotFoundException("User name not found");
        }
        if (passwordEncoder.matches(password, optionalUser.get().getPassword())) {
            return new UsernamePasswordAuthenticationToken(username, password, getAuthorities(optionalUser.get().getRoles()));
        } else {
            throw new UsernameNotFoundException("Password is wrong");
        }
    }

    private List<SimpleGrantedAuthority> getAuthorities(Set<RoleEntity> roleEntitySet) {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        for (RoleEntity entity :
                roleEntitySet) {
            authorities.add(new SimpleGrantedAuthority(entity.getRole()));
        }
        return authorities;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
