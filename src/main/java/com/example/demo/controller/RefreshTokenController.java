package com.example.demo.controller;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.demo.entity.RoleEntity;
import com.example.demo.entity.UserEntity;
import com.example.demo.repository.UserRepository;
import com.example.demo.response.BaseResponse;
import com.example.demo.response.JWTResponse;
import com.example.demo.token.tokenConfiguration;
import com.fasterxml.jackson.databind.ObjectMapper;
import javassist.tools.web.BadHttpRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@RestController
public class RefreshTokenController {
    @Autowired
    private UserRepository userRepository;
    private final static String BEARER_TYPE = "Bearer ";

    @GetMapping(value = "/token/refresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith(BEARER_TYPE)) {
            try {
                String refreshToken = authorizationHeader.substring(BEARER_TYPE.length());
                Algorithm algorithm = Algorithm.HMAC256("quynh".getBytes());
                DecodedJWT decodedJWT = tokenConfiguration.validateToken("Refresh Token", refreshToken, algorithm, response);
                String username = decodedJWT.getSubject();
                Optional<UserEntity> optionalUser = userRepository.findByUsername(username);
                if (!optionalUser.isPresent()) {
                    throw new UsernameNotFoundException("Username or password is wrong");
                }
                List<String> roles = optionalUser.get().getRoles().stream().map(RoleEntity::getRole).collect(Collectors.toList());
                String accessToken = tokenConfiguration.generateAcessToken(request, username, algorithm, roles);
                response.setStatus(HttpServletResponse.SC_OK);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                Map<String, Object> jwtResponse = JWTResponse.generate(username, roles, accessToken, refreshToken);
                Map<String, Object> baseResponse = BaseResponse.generate("Create access token success", "200", jwtResponse);
                new ObjectMapper().writeValue(response.getOutputStream(), baseResponse);
            } catch (Exception e) {
                throw new IOException(e.getMessage());
            }
        } else {
            throw new IOException("Authorization Header does not start with Bearer type");
        }
    }
}
