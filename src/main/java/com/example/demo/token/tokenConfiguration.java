package com.example.demo.token;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.List;

@Service
public class tokenConfiguration {
    public static String generateAcessToken(HttpServletRequest request, String username, Algorithm algorithm, List<String>roles){
        return JWT.create()
                .withSubject(username)
                .withExpiresAt(new Date(System.currentTimeMillis() + 2 * 60 * 60 * 1000))
                .withClaim("roles:" ,roles)
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);
    }
    public static String generateRefreshToken(HttpServletRequest request, String username, Algorithm algorithm){
        return JWT.create()
                .withSubject(username)
                .withExpiresAt(new Date(System.currentTimeMillis() + 2 * 60 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);
    }
}
