package com.example.auth.service.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccessDenyController {

    @GetMapping("/403")
    public String accessDenied(){
        System.out.println("inside access denied");
        return "Access Denied";
    }
}
