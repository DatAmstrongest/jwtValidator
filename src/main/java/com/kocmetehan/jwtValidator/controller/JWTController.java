package com.kocmetehan.jwtValidator.controller;

import com.kocmetehan.jwtValidator.response.JWTResponse;
import com.kocmetehan.jwtValidator.service.TokenValidationService;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

@RestController
public class JWTController {

    private final TokenValidationService tokenValidationService;

    private final Bucket bucket;

    public JWTController(TokenValidationService theTokenVerificationService, @Value("${ratelimit.request.per.minute}") int requestPerMinute){
        tokenValidationService = theTokenVerificationService;

        //Creating the bucket for rate limiting
        Bandwidth limit = Bandwidth.builder()
                .capacity(requestPerMinute)
                .refillGreedy(requestPerMinute, Duration.ofMinutes(1))
                .build();

        this.bucket = Bucket.builder()
                .addLimit(limit)
                .build();
    }
    // It authenticates given JWT token in Authorization part of the header
    @GetMapping("/auth")
    ResponseEntity<JWTResponse> validateJWT(@RequestHeader(value = "Authorization", required = false) String authHeader){
        if (bucket.tryConsume(1)){
            JWTResponse response = tokenValidationService.validateToken(authHeader);
            if (response.getMessage() != null) {
                return ResponseEntity.badRequest().body(response);
            }
            return ResponseEntity.ok(response);
        }
        else{
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).build();
        }
    }
}
