package com.kocmetehan.jwtValidator;

import com.kocmetehan.jwtValidator.controller.CertificateMockController;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class AuthControllerWithMockCertificateTest {

    private static final String BEARER_PREFIX_MESSAGE = "Authorization header must begin with 'Bearer '";
    private static final String TOKEN_TYPE_MESSAGE = "Invalid or missing token type. Expected 'JWT'.";
    private static final String ALGORITHM_MESSAGE = "Invalid algorithm. Only RS256 is supported.";
    private static final String MISSING_X5U_MESSAGE = "Missing 'x5u' header parameter.";
    private static final String NON_RSA_MESSAGE = "Certificate does not contain an RSA public key.";
    private static final String SIGNATURE_MESSAGE = "Signature verification failed.";
    private static final String EXPIRED_MESSAGE = "Token has expired.";
    private static final String ISSUE_TIME_MESSAGE = "Token issue time (iat) is invalid or in the future.";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CertificateMockController mockCertificateController;

    @LocalServerPort
    private int port;

    @Test
    @DisplayName("Should sign JWT with MockCertificateController's private key and validate successfully")
    void shouldValidateJwtSignedWithControllerPrivateKey() throws Exception {
        String bearerToken = validBearerToken(new Date(), Date.from(Instant.now().plus(1, ChronoUnit.HOURS)));

        mockMvc.perform(get("/auth").header("Authorization", bearerToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.message").doesNotExist());
    }

    @Test
    @DisplayName("Should accept a token issued inside the 60-second grace window")
    void shouldAcceptTokenIssuedWithinGraceWindow() throws Exception {
        Date issuedAt = Date.from(Instant.now().plus(30, ChronoUnit.SECONDS));
        Date expiresAt = Date.from(Instant.now().plus(1, ChronoUnit.HOURS));

        expectValid(validBearerToken(issuedAt, expiresAt));
    }

    @Test
    @DisplayName("Should reject a missing Authorization header")
    void shouldRejectMissingAuthorizationHeader() throws Exception {
        expectInvalid(null, BEARER_PREFIX_MESSAGE);
    }

    @Test
    @DisplayName("Should reject an Authorization header that does not use the Bearer scheme")
    void shouldRejectAuthorizationHeaderWithoutBearerPrefix() throws Exception {
        expectInvalid("Basic " + validBearerToken(issuedNow(), expiresInOneHour()).substring(7), BEARER_PREFIX_MESSAGE);
    }

    @Test
    @DisplayName("Should reject a malformed token")
    void shouldRejectMalformedToken() throws Exception {
        expectValidationError("Bearer this-is-not-a-jwt");
    }

    @Test
    @DisplayName("Should reject a token with no type")
    void shouldRejectMissingTokenType() throws Exception {
        String token = signedBearerToken(signingKey(), JWSAlgorithm.RS256, null, mockCertUri(), issuedNow(), expiresInOneHour());

        expectInvalid(token, TOKEN_TYPE_MESSAGE);
    }

    @Test
    @DisplayName("Should reject a token whose type is not JWT")
    void shouldRejectUnexpectedTokenType() throws Exception {
        String token = signedBearerToken(
                signingKey(),
                JWSAlgorithm.RS256,
                new JOSEObjectType("at+jwt"),
                mockCertUri(),
                issuedNow(),
                expiresInOneHour());

        expectInvalid(token, TOKEN_TYPE_MESSAGE);
    }

    @Test
    @DisplayName("Should reject a token whose algorithm is not RS256")
    void shouldRejectUnsupportedAlgorithm() throws Exception {
        String token = signedBearerToken(
                signingKey(),
                JWSAlgorithm.RS384,
                JOSEObjectType.JWT,
                mockCertUri(),
                issuedNow(),
                expiresInOneHour());

        expectInvalid(token, ALGORITHM_MESSAGE);
    }

    @Test
    @DisplayName("Should reject a token with no x5u header")
    void shouldRejectMissingCertificateUrl() throws Exception {
        String token = signedBearerToken(signingKey(), JWSAlgorithm.RS256, JOSEObjectType.JWT, null, issuedNow(), expiresInOneHour());

        expectInvalid(token, MISSING_X5U_MESSAGE);
    }

    @Test
    @DisplayName("Should reject a token when the certificate URL is not available")
    void shouldRejectWhenCertificateDownloadFails() throws Exception {
        URI missingCertificate = URI.create("http://localhost:" + port + "/api/mock/missing-cert");
        String token = signedBearerToken(signingKey(), JWSAlgorithm.RS256, JOSEObjectType.JWT, missingCertificate, issuedNow(), expiresInOneHour());

        expectInvalid(token, "Validation error: Failed to download certificate from x5u URL (HTTP 404)");
    }

    @Test
    @DisplayName("Should reject a token when the certificate payload is not an X.509 certificate")
    void shouldRejectWhenCertificateIsNotX509() throws Exception {
        HttpServer server = serve("not a certificate".getBytes());
        try {
            String token = signedBearerToken(signingKey(), JWSAlgorithm.RS256, JOSEObjectType.JWT, certificateUri(server), issuedNow(), expiresInOneHour());

            expectValidationError(token);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("Should reject a token when the certificate key is not RSA")
    void shouldRejectWhenCertificateIsNotRsa() throws Exception {
        HttpServer server = serve(ecCertificateBytes());
        try {
            String token = signedBearerToken(signingKey(), JWSAlgorithm.RS256, JOSEObjectType.JWT, certificateUri(server), issuedNow(), expiresInOneHour());

            expectInvalid(token, NON_RSA_MESSAGE);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("Should reject a token with an invalid signature")
    void shouldRejectInvalidSignature() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        PrivateKey otherKey = generator.generateKeyPair().getPrivate();
        String token = signedBearerToken(otherKey, JWSAlgorithm.RS256, JOSEObjectType.JWT, mockCertUri(), issuedNow(), expiresInOneHour());

        expectInvalid(token, SIGNATURE_MESSAGE);
    }

    @Test
    @DisplayName("Should reject an expired token")
    void shouldRejectExpiredToken() throws Exception {
        Date issuedAt = Date.from(Instant.now().minus(10, ChronoUnit.MINUTES));
        Date expiresAt = Date.from(Instant.now().minus(5, ChronoUnit.MINUTES));

        expectInvalid(validBearerToken(issuedAt, expiresAt), EXPIRED_MESSAGE);
    }

    @Test
    @DisplayName("Should reject a token with no expiration")
    void shouldRejectTokenWithoutExpiration() throws Exception {
        expectInvalid(validBearerToken(issuedNow(), null), EXPIRED_MESSAGE);
    }

    @Test
    @DisplayName("Should reject a token issued in the future")
    void shouldRejectTokenIssuedInTheFuture() throws Exception {
        Date issuedAt = Date.from(Instant.now().plus(2, ChronoUnit.MINUTES));

        expectInvalid(validBearerToken(issuedAt, expiresInOneHour()), ISSUE_TIME_MESSAGE);
    }

    @Test
    @DisplayName("Should reject a token with no issue time")
    void shouldRejectTokenWithoutIssueTime() throws Exception {
        expectInvalid(validBearerToken(null, expiresInOneHour()), ISSUE_TIME_MESSAGE);
    }

    private String validBearerToken(Date issuedAt, Date expiresAt) throws Exception {
        return signedBearerToken(signingKey(), JWSAlgorithm.RS256, JOSEObjectType.JWT, mockCertUri(), issuedAt, expiresAt);
    }

    private String signedBearerToken(PrivateKey signingKey, JWSAlgorithm algorithm, JOSEObjectType type,
                                     URI certificateUrl, Date issuedAt, Date expiresAt) throws Exception {
        JWSHeader.Builder header = new JWSHeader.Builder(algorithm);
        if (type != null) {
            header.type(type);
        }
        if (certificateUrl != null) {
            header.x509CertURL(certificateUrl);
        }

        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .subject("1234567890")
                .claim("name", "John Doe");
        if (issuedAt != null) {
            claims.issueTime(issuedAt);
        }
        if (expiresAt != null) {
            claims.expirationTime(expiresAt);
        }

        SignedJWT signedJWT = new SignedJWT(header.build(), claims.build());
        signedJWT.sign(new RSASSASigner(signingKey));
        return "Bearer " + signedJWT.serialize();
    }

    private void expectValid(String authorization) throws Exception {
        performAuth(authorization)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.message").doesNotExist());
    }

    private void expectInvalid(String authorization, String message) throws Exception {
        performAuth(authorization)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.message").value(message));
    }

    private void expectValidationError(String authorization) throws Exception {
        performAuth(authorization)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.message").value(startsWith("Validation error:")));
    }

    private ResultActions performAuth(String authorization) throws Exception {
        var request = get("/auth");
        if (authorization != null) {
            request.header("Authorization", authorization);
        }
        return mockMvc.perform(request);
    }

    private PrivateKey signingKey() {
        return mockCertificateController.getPrivateKey();
    }

    private URI mockCertUri() {
        return URI.create("http://localhost:" + port + "/api/mock/certs");
    }

    private Date issuedNow() {
        return new Date();
    }

    private Date expiresInOneHour() {
        return Date.from(Instant.now().plus(1, ChronoUnit.HOURS));
    }

    private HttpServer serve(byte[] body) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/cert", exchange -> {
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream output = exchange.getResponseBody()) {
                output.write(body);
            }
        });
        server.start();
        return server;
    }

    private URI certificateUri(HttpServer server) {
        return URI.create("http://localhost:" + server.getAddress().getPort() + "/cert");
    }

    private byte[] ecCertificateBytes() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = generator.generateKeyPair();

        X500Name subject = new X500Name("CN=ec-test, O=Test, C=US");
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(
                        subject,
                        BigInteger.ONE,
                        new Date(System.currentTimeMillis() - 60_000),
                        Date.from(Instant.now().plus(1, ChronoUnit.DAYS)),
                        subject,
                        keyPair.getPublic()
                ).build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));
        return certificate.getEncoded();
    }
}
