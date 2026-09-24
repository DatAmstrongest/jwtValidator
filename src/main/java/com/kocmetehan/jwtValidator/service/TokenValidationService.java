package com.kocmetehan.jwtValidator.service;

import com.kocmetehan.jwtValidator.response.JWTResponse;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Date;

@Service
public class TokenValidationService {

    private static final Logger log = LoggerFactory.getLogger(TokenValidationService.class);

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .build();

    public JWTResponse validateToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return reject("Authorization header must begin with 'Bearer '");
        }

        String token = authHeader.substring(7).trim();

        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            // 1. Validate Type (typ)
            JOSEObjectType typ = signedJWT.getHeader().getType();
            if (typ == null || !"JWT".equalsIgnoreCase(typ.getType())) {
                return reject("Invalid or missing token type. Expected 'JWT'.");
            }

            // 2. Validate Algorithm
            if (!JWSAlgorithm.RS256.equals(signedJWT.getHeader().getAlgorithm())) {
                return reject("Invalid algorithm. Only RS256 is supported.");
            }

            // 3. Validate x5u
            URI x5u = signedJWT.getHeader().getX509CertURL();
            if (x5u == null) {
                return reject("Missing 'x5u' header parameter.");
            }

            // 4. Fetch & Parse X.509 Certificate
            X509Certificate certificate = fetchCertificate(x5u);
            if (!(certificate.getPublicKey() instanceof RSAPublicKey rsaPublicKey)) {
                return reject("Certificate does not contain an RSA public key.");
            }

            // 5. Verify Signature
            RSASSAVerifier verifier = new RSASSAVerifier(rsaPublicKey);
            if (!signedJWT.verify(verifier)) {
                return reject("Signature verification failed.");
            }

            // 6. Verify Claims (iat & exp)
            Date now = new Date();
            Date exp = signedJWT.getJWTClaimsSet().getExpirationTime();
            Date iat = signedJWT.getJWTClaimsSet().getIssueTime();

            // Check if the token is expired or not
            if (exp == null || now.after(exp)) {
                return reject("Token has expired.");
            }

            // Check if the current time is before the issue time
            if (iat == null || now.before(new Date(iat.getTime()))) {
                return reject("Token issue time (iat) is invalid or in the future.");
            }

            log.info("JWT validated");
            return new JWTResponse(true, null);

        } catch (Exception e) {
            log.error("JWT validation failed: {}", e.getMessage());
            return new JWTResponse(false, "Validation error: " + e.getMessage());
        }
    }

    private JWTResponse reject(String message) {
        log.warn("JWT rejected: {}", message);
        return new JWTResponse(false, message);
    }

    // This function gets the certificate from a given URL.
    private X509Certificate fetchCertificate(URI x5u) throws Exception {
        log.info("Fetching certificate from {}", x5u);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(x5u)
                .timeout(Duration.ofSeconds(3))
                .GET()
                .build();

        HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) {
            log.warn("Certificate download from {} failed with HTTP {}", x5u, response.statusCode());
            throw new IllegalStateException("Failed to download certificate from x5u URL (HTTP " + response.statusCode() + ")");
        }
        log.info("Downloaded certificate from {}", x5u);

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(response.body()));
    }
}
