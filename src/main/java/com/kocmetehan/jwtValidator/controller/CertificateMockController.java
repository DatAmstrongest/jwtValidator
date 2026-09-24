package com.kocmetehan.jwtValidator.controller;

import jakarta.annotation.PostConstruct;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.FileWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

// This is the mock certificate server that creates private and public keys, saves them and returned them from an endpoint
@RestController
@RequestMapping("/api/mock")
public class CertificateMockController {

    private static final Logger log = LoggerFactory.getLogger(CertificateMockController.class);

    private byte[] cachedCertificateBytes;
    private PrivateKey privateKey; // Kept in memory if you want to sign tokens from the app

    @PostConstruct
    public void init() throws Exception {
        // 1. Generate RSA 2048-bit KeyPair
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        this.privateKey = keyPair.getPrivate();

        // 2. Build Self-Signed X.509 Certificate
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now);
        Date notAfter = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));
        X500Name subjectAndIssuer = new X500Name("CN=localhost, O=MockAuth, C=US");

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subjectAndIssuer,
                BigInteger.valueOf(now),
                notBefore,
                notAfter,
                subjectAndIssuer,
                keyPair.getPublic()
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

        // Cache DER-encoded bytes in memory for fast HTTP responses
        this.cachedCertificateBytes = certificate.getEncoded();

        // 3. Write files to src/main/resources/certs/
        saveFilesToResources(certificate, keyPair.getPrivate());
    }

    private void saveFilesToResources(X509Certificate certificate, PrivateKey privateKey) {
        try {
            Path dir = Paths.get("src/main/resources/certs");
            Files.createDirectories(dir);

            // Write Certificate (.crt in PEM format)
            Path certPath = dir.resolve("mock-cert.crt");
            try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(certPath.toFile()))) {
                pemWriter.writeObject(certificate);
            }

            // Write Private Key (.pem in PKCS#8 format for JWT signing)
            Path keyPath = dir.resolve("mock-key.pem");
            try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(keyPath.toFile()))) {
                pemWriter.writeObject(privateKey);
            }

            log.info("Saved mock certificates to {}", dir.toAbsolutePath());
        } catch (Exception e) {
            log.warn("Could not save mock certificates to src/main/resources/certs: {}", e.getMessage());
        }
    }

    // Endpoint returning the certificate directly
    @GetMapping(value = "/certs", produces = "application/x-x509-ca-cert")
    public ResponseEntity<byte[]> getCertificate() {
        log.info("Serving mock certificate");
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, "application/x-x509-ca-cert")
                .body(this.cachedCertificateBytes);
    }

    // Getter in case you want to access the private key for signing inside tests
    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }
}