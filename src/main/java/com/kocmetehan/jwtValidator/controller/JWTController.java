package com.kocmetehan.jwtValidator.controller;

import com.kocmetehan.jwtValidator.response.JWTResponse;
import com.kocmetehan.jwtValidator.service.TokenValidationService;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@RestController
public class JWTController {

    private static final Logger log = LoggerFactory.getLogger(JWTController.class);

    private final TokenValidationService tokenValidationService;

    private final Bandwidth limit;

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    public JWTController(TokenValidationService theTokenVerificationService, @Value("${ratelimit.request.per.minute}") int requestPerMinute){
        tokenValidationService = theTokenVerificationService;

        // Each client gets its own bucket with this limit
        limit = Bandwidth.builder()
                .capacity(requestPerMinute)
                .refillGreedy(requestPerMinute, Duration.ofMinutes(1))
                .build();
        log.info("Rate limit configured at {} requests per minute per client", requestPerMinute);
    }
    // It authenticates given JWT token in Authorization part of the header
    @GetMapping("/auth")
    ResponseEntity<JWTResponse> validateJWT(@RequestHeader(value = "Authorization", required = false) String authHeader,
                                            HttpServletRequest request){
        Bucket bucket = buckets.computeIfAbsent(request.getRemoteAddr(), _ -> Bucket.builder().addLimit(limit).build());
        if (bucket.tryConsume(1)){
            JWTResponse response = tokenValidationService.validateToken(authHeader);
            if (response.getMessage() != null) {
                log.warn("Authentication rejected: {}", response.getMessage());
                return ResponseEntity.badRequest().body(response);
            }
            log.info("Authentication succeeded");
            return ResponseEntity.ok(response);
        }
        else{
            log.warn("Rate limit exceeded for {}", request.getRemoteAddr());
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).build();
        }
    }
}
