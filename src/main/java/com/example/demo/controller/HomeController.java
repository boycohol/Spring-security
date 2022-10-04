package com.example.demo.controller;

import com.example.demo.entity.UserEntity;
import com.example.demo.model.ResponseModel;
import com.example.demo.model.UserModel;
import com.example.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.transaction.Transactional;
import java.util.Optional;

@RestController

public class HomeController {
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private UserRepository userRepository;

    @PostMapping("/register")
    @Transactional
    public UserEntity register(@RequestBody UserModel userModel) {
        UserEntity user = new UserEntity(userModel.getId(), userModel.getUsername(),
                passwordEncoder.encode(userModel.getPassword()), true, userModel.getRoles());
        return userRepository.save(user);
    }
    @GetMapping("/finduser")
    public UserEntity findbyUsername(@RequestParam String username){
        Optional<UserEntity>user= userRepository.findByUsername(username);
        return user.orElse(null);
    }
   /* @PostMapping("/login")
    public ResponseModel login(@RequestBody UserModel userModel) {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userModel.getUsername(), userModel.getPassword()));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (UsernameNotFoundException e) {
            return new ResponseModel(e.getMessage(), HttpStatus.BAD_REQUEST, null);
        }
        return new ResponseModel("Login success", HttpStatus.OK, null);
    }*/

}
