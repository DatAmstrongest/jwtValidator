package com.kocmetehan.jwtValidator;

import com.kocmetehan.jwtValidator.controller.CertificateMockController;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import java.net.URI;
import java.security.PrivateKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// 1. Tell Spring Boot to start a real embedded Tomcat server on a free port
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class AuthControllerWithMockCertificateTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CertificateMockController mockCertificateController;

    // 2. Inject the dynamic port Tomcat is listening on
    @LocalServerPort
    private int port;

    @Test
    @DisplayName("Should sign JWT with MockCertificateController's private key and validate successfully")
    void shouldValidateJwtSignedWithControllerPrivateKey() throws Exception {
        PrivateKey signingKey = mockCertificateController.getPrivateKey();

        // 3. Include the actual port so HttpClient can connect to the running Tomcat
        String certUrl = "http://localhost:" + port + "/api/mock/certs";

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(com.nimbusds.jose.JOSEObjectType.JWT)
                .x509CertURL(URI.create(certUrl))
                .build();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("1234567890")
                .claim("name", "John Doe")
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)))
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claims);
        JWSSigner signer = new RSASSASigner(signingKey);
        signedJWT.sign(signer);

        String bearerToken = "Bearer " + signedJWT.serialize();

        // 4. Perform the call
        mockMvc.perform(get("/auth")
                        .header("Authorization", bearerToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));
    }
}