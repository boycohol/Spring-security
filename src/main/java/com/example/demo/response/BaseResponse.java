package com.example.demo.response;

import java.util.HashMap;
import java.util.Map;

public class BaseResponse {
    public static Map<String,Object> generate(String message, String status, Object data){
        Map<String,Object> response=new HashMap<>();
        response.put("message: ",message);
        response.put("status: ",status);
        response.put("data: ",data);
        return response;
    }
}
