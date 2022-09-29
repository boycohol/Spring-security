package com.example.demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SuperAdminController {
    @GetMapping(value = "/profile")
    public String superAdminHome(){
        return "You're in profile - Super Admin";
    }
}
