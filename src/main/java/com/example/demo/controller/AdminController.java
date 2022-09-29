package com.example.demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminController {
    @GetMapping("/dashboard")
    public String adminDashboard(){
        return "You're in admin dashboard";
    }
}
