package com.kocmetehan.jwtValidator.controller;

import com.kocmetehan.jwtValidator.response.JWTResponse;
import com.kocmetehan.jwtValidator.service.TokenVerificationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class JWTController {
    private TokenVerificationService tokenVerificationService;
    public JWTController(TokenVerificationService theTokenVerificationService){
        tokenVerificationService = theTokenVerificationService;
    }
    //TODO: Ask Fedor what to return in exceptions
    @GetMapping("/auth")
    JWTResponse validateJWT(@RequestHeader(value = "Authorization", required = false) String authHeader){
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return new JWTResponse(false);
        }
        String token = authHeader.substring(7);
        Boolean isValid = tokenVerificationService.validateToken(token);
        return new JWTResponse(isValid);
    }
}
