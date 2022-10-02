package com.example.demo.filter;

import com.auth0.jwt.algorithms.Algorithm;
import com.example.demo.model.CustomUser;
import com.example.demo.request.UsernameAndPasswordRequest;
import com.example.demo.response.BaseResponse;
import com.example.demo.response.JWTResponse;
import com.example.demo.token.tokenConfiguration;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    @Autowired
    private AuthenticationManager authenticationManager;

    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (!HttpMethod.POST.matches(request.getMethod())) {
            throw new AuthenticationServiceException("Authentication method does not support: " + request.getMethod());
        }
        UsernameAndPasswordRequest usernameAndPasswordRequest = new ObjectMapper()
                .readValue(request.getInputStream(), UsernameAndPasswordRequest.class);
        try {
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            usernameAndPasswordRequest.getUsername(),
                            usernameAndPasswordRequest.getPassword()));
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            Map<String, Object> customResponse = BaseResponse.generate("Username or Password is wrong", "401", null);
            new ObjectMapper().writeValue(response.getOutputStream(), customResponse);
            throw new UsernameNotFoundException(e.getMessage());
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        CustomUser user = (CustomUser) authResult.getPrincipal();
        Algorithm algorithm = Algorithm.HMAC256("quynh".getBytes());
        List<String> roles = new ArrayList<>();
        List<GrantedAuthority> authorities = (List<GrantedAuthority>) user.getAuthorities();
        for (GrantedAuthority authority :
                authorities) {
            roles.add(authority.getAuthority());
        }
        String accessToken = tokenConfiguration.generateAcessToken(request, user, algorithm, roles);
        String refreshToken = tokenConfiguration.generateRefreshToken(request, user, algorithm);
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        Map<String,Object> JwtResponse = JWTResponse.generate(user.getUsername(),roles,accessToken,refreshToken);
        Map<String,Object> customResponse=BaseResponse.generate("Login success!","200",JwtResponse);
        new ObjectMapper().writeValue(response.getOutputStream(),customResponse);
    }
}
