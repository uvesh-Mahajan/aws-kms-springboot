package com.example.kms.service;

import java.util.Base64;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

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
