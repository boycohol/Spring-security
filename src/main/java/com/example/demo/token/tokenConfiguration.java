package com.example.demo.token;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.demo.response.BaseResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

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
    @SneakyThrows
    public static DecodedJWT validateToken(String keyType, String token, Algorithm algorithm, HttpServletResponse response){
        try{
            JWTVerifier verifier = JWT.require(algorithm).build();
            return verifier.verify(token);
        } catch (Exception e) {
            response.setStatus(SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            Map<String, Object> customResponse = BaseResponse.generate("401", "The " + keyType + " has expired!", null);
            new ObjectMapper().writeValue(response.getOutputStream(),customResponse);
            throw new UnavailableException("The"  + keyType + " has expired!");
        }
    }
}
