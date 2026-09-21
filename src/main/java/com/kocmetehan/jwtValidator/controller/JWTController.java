package com.kocmetehan.jwtValidator.controller;

import com.kocmetehan.jwtValidator.response.JWTResponse;
import com.kocmetehan.jwtValidator.service.TokenValidationService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JWTController {
    private TokenValidationService tokenValidationService;
    public JWTController(TokenValidationService theTokenVerificationService){
        tokenValidationService = theTokenVerificationService;
    }
    //TODO: Ask Fedor what to return in exceptions
    //TODO: Changes status code with respect to existence of the message
    @GetMapping("/auth")
    JWTResponse validateJWT(@RequestHeader(value = "Authorization", required = false) String authHeader){
        return tokenValidationService.validateToken(authHeader);
    }
}
