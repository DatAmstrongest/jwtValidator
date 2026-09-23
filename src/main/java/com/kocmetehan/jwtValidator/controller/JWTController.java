package com.kocmetehan.jwtValidator.controller;

import com.kocmetehan.jwtValidator.response.JWTResponse;
import com.kocmetehan.jwtValidator.service.TokenValidationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JWTController {

    private final TokenValidationService tokenValidationService;

    public JWTController(TokenValidationService theTokenVerificationService){
        tokenValidationService = theTokenVerificationService;
    }

    @GetMapping("/auth")
    ResponseEntity<JWTResponse> validateJWT(@RequestHeader(value = "Authorization", required = false) String authHeader){
        JWTResponse response = tokenValidationService.validateToken(authHeader);
        if (response.getMessage() != null) {
            return ResponseEntity.badRequest().body(response);
        }
        return ResponseEntity.ok(response);
    }
}
