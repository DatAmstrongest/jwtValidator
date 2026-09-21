package com.kocmetehan.jwtValidator.service;

import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPublicKey;

@Service
public class TokenVerificationService {

    public Boolean validateToken(String token){
        System.out.println(token);
        return true;
    }

    private RSAPublicKey getPublicKey(String url){
        return null;
    }
}
