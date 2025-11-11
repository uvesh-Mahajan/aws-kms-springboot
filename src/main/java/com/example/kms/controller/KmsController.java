package com.example.kms.controller;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import com.example.kms.service.KmsFactory;
import com.example.kms.service.KmsKeyOperationsService;
import com.example.kms.service.KmsSymmetricKeyService;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;

@RestController
@RequestMapping("/kms")
public class KmsController {

    @Autowired
    private KmsFactory kmsFactory;
    
    @Autowired
    public KmsSymmetricKeyService kmsSymmetricKeyService;

    @Value("${aws.kms.keyCreationProcess}")
    private String keyCreationProcess;

    private volatile JWKSet cachedJwkSet;
    private final Duration cacheTtl = Duration.ofMinutes(10);
    private volatile Instant cacheExpiry = Instant.EPOCH;
    
 
    
    @PostMapping("/create-key/{alias}")
    public String createKey(@PathVariable String alias) {
        return kmsSymmetricKeyService.createSymmetricKey(alias);
    }

    @PostMapping("/encrypt")
    public Map<String, String> encrypt(@RequestBody Map<String, String> payload) {
        String text = payload.get("text");
        KmsKeyOperationsService kmsService = kmsFactory.getService(keyCreationProcess);
        String cipher = kmsService.encrypt(text);
        return Map.of("cipherText", cipher);
    }

    @PostMapping("/decrypt")
    public Map<String, String> decrypt(@RequestBody Map<String, String> payload) {
        String cipher = payload.get("cipher");
        KmsKeyOperationsService kmsService = kmsFactory.getService(keyCreationProcess);
        String plain = kmsService.decrypt(cipher);
        return Map.of("plainText", plain);
    }

    @GetMapping("/jwks.json")
    public Map<String, Object> jwks() throws Exception {
        KmsKeyOperationsService kmsService = kmsFactory.getService(keyCreationProcess);
        return kmsService.getJwks();
    }

    /**
     * Create a detached JWS (header + payload + signature)
     */
    @PostMapping("/sign")
    public String sign(@RequestBody Map<String, Object> payload) throws Exception {
        KmsKeyOperationsService kmsService = kmsFactory.getService(keyCreationProcess);
        RSAKey rsaKey = (RSAKey) kmsService.jwkFromKms();

        // Create JWS header
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaKey.getKeyID())
                .type(JOSEObjectType.JOSE)
                .build();

        // Payload
        Payload jwsPayload = new Payload(com.nimbusds.jose.util.JSONObjectUtils.toJSONString(payload));

        // JWS object (header + payload)
        JWSObject jwsObject = new JWSObject(header, jwsPayload);

        // Create digest
        String signingInput = new String(jwsObject.getSigningInput(), StandardCharsets.US_ASCII);

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(signingInput.getBytes(StandardCharsets.US_ASCII));

        // Sign using AWS KMS
        KmsClient kms = kmsService.getKmsClient();
        SignRequest req = SignRequest.builder()
                .keyId(rsaKey.getKeyID())
                .message(SdkBytes.fromByteArray(digest))
                .messageType("DIGEST")
                .signingAlgorithm("RSASSA_PKCS1_V1_5_SHA_256")
                .build();

        SignResponse resp = kms.sign(req);
        Base64URL signature = Base64URL.encode(resp.signature().asByteArray());

        // Attach signature
        return signingInput + "." + signature;
    }

    /**
     * Verify a JWS (header + payload + signature)
     */
    @PostMapping("/verify")
    public Map<String, Object> verify(@RequestBody Map<String, String> body) throws Exception {
        KmsKeyOperationsService kmsService = kmsFactory.getService(keyCreationProcess);
        String jwsCompact = body.get("token");

        // Parse compact JWS string
        JWSObject jwsObject = JWSObject.parse(jwsCompact);

        RSAKey rsaKey = (RSAKey) kmsService.jwkFromKms();
        boolean verified = jwsObject.verify(new RSASSAVerifier(rsaKey));

        Map<String, Object> result = new HashMap<>();
        result.put("verified", verified);
        result.put("payload", jwsObject.getPayload().toJSONObject());
        return result;
    }
}
