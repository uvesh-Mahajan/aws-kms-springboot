package com.example.kms.service;

import java.util.Base64;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.AliasListEntry;
import software.amazon.awssdk.services.kms.model.CreateAliasRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyResponse;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.ListAliasesResponse;

@Service("DYNAMIC")
public class KmsDynamicService implements KmsKeyOperationsService {

    @Value("${aws.region}")
    private String region;

    @Value("${aws.kms.alias-name}")
    private String aliasName;

    @Value("${aws.credentials.access-key:}")
    private String accessKey;

    @Value("${aws.credentials.secret-key:}")
    private String secretKey;

    private KmsClient kmsClient;
    private String kmsKeyId;

    
    public void init() {
        AwsCredentialsProvider credentialsProvider =
                (accessKey.isBlank() || secretKey.isBlank())
                        ? DefaultCredentialsProvider.create()
                        : StaticCredentialsProvider.create(AwsBasicCredentials.create(accessKey, secretKey));

        kmsClient = KmsClient.builder()
                .region(Region.of(region))
                .credentialsProvider(credentialsProvider)
                .build();

        ensureKeyExists();
    }

    private void ensureKeyExists() {
        // Check if alias already exists
        ListAliasesResponse aliases = kmsClient.listAliases();

        String existingKeyId = aliases.aliases().stream()
                .filter(a -> aliasName.equals(a.aliasName()))
                .map(AliasListEntry::targetKeyId)
                .findFirst()
                .orElse(null);

        if (existingKeyId != null) {
            this.kmsKeyId = existingKeyId;
            System.out.println("Existing KMS Key found: " + kmsKeyId);
        } else {
            // Create new KMS key
            CreateKeyResponse keyResponse = kmsClient.createKey(CreateKeyRequest.builder()
                    .description("Spring Boot generated key for dynamic encryption/decryption")
                    .keyUsage(KeyUsageType.ENCRYPT_DECRYPT)
                    .build());

            this.kmsKeyId = keyResponse.keyMetadata().keyId();
            System.out.println("🔑 Created new KMS Key: " + kmsKeyId);

            // Create alias for easier lookup
            kmsClient.createAlias(CreateAliasRequest.builder()
                    .aliasName(aliasName)
                    .targetKeyId(kmsKeyId)
                    .build());
            System.out.println("Alias created: " + aliasName);
        }
    }

    public String encrypt(String plainText) {

    	init();
    	SdkBytes sdkBytes = SdkBytes.fromByteArray(plainText.getBytes());

        EncryptRequest request = EncryptRequest.builder()
                .keyId(kmsKeyId)
                .plaintext(sdkBytes)
                .build();

        EncryptResponse response = kmsClient.encrypt(request);
        return Base64.getEncoder().encodeToString(response.ciphertextBlob().asByteArray());
    }

    public String decrypt(String encryptedText) {
        byte[] decoded = Base64.getDecoder().decode(encryptedText);
        
        SdkBytes sdkBytes = SdkBytes.fromByteArray(decoded);

        DecryptRequest request = DecryptRequest.builder()
                .ciphertextBlob(sdkBytes)
                .build();

        DecryptResponse response = kmsClient.decrypt(request);
        return new String(response.plaintext().asByteArray());
    }
}

