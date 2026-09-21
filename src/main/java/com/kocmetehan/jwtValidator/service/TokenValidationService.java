package com.kocmetehan.jwtValidator.service;

import com.kocmetehan.jwtValidator.response.JWTResponse;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.apache.tomcat.websocket.AsyncChannelWrapperSecure;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

@Service
public class TokenValidationService {
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .build();

    public JWTResponse validateToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return new JWTResponse(false, "Authorization header must begin with 'Bearer '");
        }

        String token = authHeader.substring(7).trim();

        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            // 1. Validate Algorithm
            if (!JWSAlgorithm.RS256.equals(signedJWT.getHeader().getAlgorithm())) {
                return new JWTResponse(false, "Invalid algorithm. Only RS256 is supported.");
            }

            // 2. Validate x5u
            URI x5u = signedJWT.getHeader().getX509CertURL();
            if (x5u == null) {
                return new JWTResponse(false, "Missing 'x5u' header parameter.");
            }

            // 3. Fetch & Parse X.509 Certificate
            X509Certificate certificate = fetchCertificate(x5u);
            if (!(certificate.getPublicKey() instanceof RSAPublicKey rsaPublicKey)) {
                return new JWTResponse(false, "Certificate does not contain an RSA public key.");
            }

            // 4. Verify Signature
            RSASSAVerifier verifier = new RSASSAVerifier(rsaPublicKey);
            if (!signedJWT.verify(verifier)) {
                return new JWTResponse(false, "Signature verification failed.");
            }

            // 5. Verify Claims (iat & exp)
            Date now = new Date();
            Date exp = signedJWT.getJWTClaimsSet().getExpirationTime();
            Date iat = signedJWT.getJWTClaimsSet().getIssueTime();

            if (exp == null || now.after(exp)) {
                return new JWTResponse(false, "Token has expired.");
            }

            // Check if the current time is before the issue time (with a 60-second grace window)
            if (iat == null || now.before(new Date(iat.getTime() - 60_000))) {
                return new JWTResponse(false, "Token issue time (iat) is invalid or in the future.");
            }

            return new JWTResponse(true, null);

        } catch (Exception e) {
            return new JWTResponse(false, "Validation error: " + e.getMessage());
        }
    }

    private X509Certificate fetchCertificate(URI x5u) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(x5u)
                .timeout(Duration.ofSeconds(3))
                .GET()
                .build();

        HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Failed to download certificate from x5u URL (HTTP " + response.statusCode() + ")");
        }

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(response.body()));
    }
}
