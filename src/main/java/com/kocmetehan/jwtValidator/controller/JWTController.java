package com.kocmetehan.jwtValidator.controller;

import com.kocmetehan.jwtValidator.response.JWTResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JWTController {
    @GetMapping("/auth")
    JWTResponse validateJWT(){
        return new JWTResponse(true);
    }
}
