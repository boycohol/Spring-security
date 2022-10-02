package com.example.demo.response;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class JWTResponse {
    public static Map<String, Object> generate(String username, List<String> roles, String accessToken, String refreshToken) {
        Map<String, Object> response = new HashMap<>();
        response.put("username: ", username);
        response.put("roles: ", roles);
        response.put("access token: ", accessToken);
        response.put("refresh token: ", refreshToken);
        return response;
    }
}
