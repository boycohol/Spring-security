package com.example.demo.filter;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.demo.token.tokenConfiguration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

public class AuthorizationFilter extends OncePerRequestFilter {
    private final static String BEARER_TYPE = "Bearer ";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getServletPath().equals("/api/login")||
                request.getServletPath().equals("/token/refresh")
        ) {
            filterChain.doFilter(request, response);
        } else {
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            if (authorizationHeader != null && authorizationHeader.startsWith(BEARER_TYPE)) {
                String accessToken = authorizationHeader.substring(BEARER_TYPE.length());
                Algorithm algorithm = Algorithm.HMAC256("quynh".getBytes());
                DecodedJWT decodedJWT = tokenConfiguration.validateToken("Access token", accessToken, algorithm, response);
                String username = decodedJWT.getSubject();
                List<String> roles = decodedJWT.getClaim("roles:").asList(String.class);
                Collection<SimpleGrantedAuthority> authorities=new ArrayList<>();
                for(String role:
                     roles) {
                    authorities.add(new SimpleGrantedAuthority(role));
                }
                UsernamePasswordAuthenticationToken authenticationToken=new UsernamePasswordAuthenticationToken(username,null,authorities);
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                filterChain.doFilter(request,response);
            }else{
                throw new UnavailableException("Authorization Header does not start with Bearer type");
            }
        }
    }
}
