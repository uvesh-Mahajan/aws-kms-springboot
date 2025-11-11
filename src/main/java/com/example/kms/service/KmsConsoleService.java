package com.example.kms.service;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import jakarta.annotation.PostConstruct;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;

@Service("CONSOLE")
public class KmsConsoleService implements KmsKeyOperationsService {

    @Value("${aws.kms.key-id}")
    private String kmsKeyId;

    @Value("${aws.region}")
    private String region;

    @Value("${aws.credentials.access-key:}")
    private String accessKey;

    @Value("${aws.credentials.secret-key:}")
    private String secretKey;

    private KmsClient kmsClient;

    @PostConstruct
    public void init() {
        AwsCredentialsProvider credentialsProvider = (accessKey.isBlank() || secretKey.isBlank())
                ? DefaultCredentialsProvider.create()
                : StaticCredentialsProvider.create(AwsBasicCredentials.create(accessKey, secretKey));

        kmsClient = KmsClient.builder()
                .region(Region.of(region))
                .credentialsProvider(credentialsProvider)
                .build();
    }
    
    
    public KmsClient getKmsClient() {
        return kmsClient;
    }
    
    public JWK jwkFromKms() throws Exception {
        // 1️⃣ Fetch public key bytes from KMS
        GetPublicKeyRequest req = GetPublicKeyRequest.builder()
                .keyId(kmsKeyId)
                .build();
        GetPublicKeyResponse resp = kmsClient.getPublicKey(req);
        byte[] der = resp.publicKey().asByteArray();

        // 2️⃣ Extract key spec & algorithm
        String keySpec = resp.keySpecAsString(); // e.g., RSA_2048, ECC_NIST_P256

        // 3️⃣ Convert DER bytes to PublicKey
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        
        System.out.println("X509EncodedKeySpec...................");
        System.out.println(spec);

        if (keySpec.startsWith("RSA")) {
            // RSA key
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pub = kf.generatePublic(spec);

            com.nimbusds.jose.JWSAlgorithm alg = com.nimbusds.jose.JWSAlgorithm.RS256;
     
            String kid = generateKidFromKmsKeyId(kmsKeyId, resp);

            RSAKey jwk = new RSAKey.Builder((java.security.interfaces.RSAPublicKey) pub)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(alg)
                    .keyID(kid)
                    .build();

            return jwk;

        } else if (keySpec.startsWith("ECC")) {
            // EC key
            KeyFactory kf = KeyFactory.getInstance("EC");
            PublicKey pub = kf.generatePublic(spec);
            java.security.interfaces.ECPublicKey ecPub = (java.security.interfaces.ECPublicKey) pub;

            // Map curve
            com.nimbusds.jose.jwk.Curve curve = com.nimbusds.jose.jwk.Curve.P_256;
            com.nimbusds.jose.JWSAlgorithm alg = com.nimbusds.jose.JWSAlgorithm.ES256;
            if (keySpec.equalsIgnoreCase("ECC_NIST_P384")) {
                curve = com.nimbusds.jose.jwk.Curve.P_384;
                alg = com.nimbusds.jose.JWSAlgorithm.ES384;
            } else if (keySpec.equalsIgnoreCase("ECC_NIST_P521")) {
                curve = com.nimbusds.jose.jwk.Curve.P_521;
                alg = com.nimbusds.jose.JWSAlgorithm.ES512;
            }

            String kid = generateKidFromKmsKeyId(kmsKeyId, resp);

            ECKey jwk = new ECKey.Builder(curve, ecPub)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(alg)
                    .keyID(kid)
                    .build();

            return jwk;
        } else {
            throw new IllegalStateException("Unsupported key spec: " + keySpec);
        }
    }
    
    
    public Map<String,Object> getJwks() throws Exception {
        JWKSet set = new JWKSet(jwkFromKms());
        return set.toJSONObject();
    }

    
    private String generateKidFromKmsKeyId(String keyId, GetPublicKeyResponse resp) {
        // Option 1: use KMS keyId (stable) as kid. Simpler & fine.
        // Option 2 (preferred for RFC7638): compute JWK thumbprint (but needs full JWK JSON).
        // We'll use the KMS keyId/ARN which is stable and traceable.
        return keyId; // e.g., "arn:aws:kms:...:key/<uuid>"
    }


    public String encrypt(String plainText) {
    	SdkBytes sdkBytes = SdkBytes.fromByteArray(plainText.getBytes());

        EncryptRequest request = EncryptRequest.builder()
                .keyId(kmsKeyId)
                .plaintext(sdkBytes)
                .build();

        EncryptResponse response = kmsClient.encrypt(request);
        return Base64.getEncoder().encodeToString(response.ciphertextBlob().asByteArray());
    }

    public String decrypt(String encryptedText) {
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        
        SdkBytes sdkBytes = SdkBytes.fromByteArray(decodedBytes);


        DecryptRequest request = DecryptRequest.builder()
                .ciphertextBlob(sdkBytes)
                .build();

        DecryptResponse response = kmsClient.decrypt(request);
        return new String(response.plaintext().asByteArray());
    }
}
