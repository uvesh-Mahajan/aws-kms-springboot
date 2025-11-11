package com.example.kms.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.AliasListEntry;
import software.amazon.awssdk.services.kms.model.CreateAliasRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyResponse;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.ListAliasesResponse;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;

@Service
public class KmsSymmetricKeyService {

	@Value("${aws.region}")
	private String awsRegion;

	@Value("${aws.kms.assume-role-arn}")
	private String assumeRoleArn;

	private AwsCredentialsProvider assumeRoleCredentialsProvider() {
		StsClient stsClient = StsClient.builder().region(Region.of(awsRegion)).build();

		AssumeRoleRequest assumeRoleRequest = AssumeRoleRequest.builder().roleArn(assumeRoleArn)
				.roleSessionName("kms-symmetric-key-session").build();

		return StsAssumeRoleCredentialsProvider.builder().stsClient(stsClient).refreshRequest(assumeRoleRequest)
				.build();
	}

	private KmsClient kmsClient() {
		return KmsClient.builder().region(Region.of(awsRegion)).credentialsProvider(assumeRoleCredentialsProvider())
				.build();
	}

	public String createSymmetricKey(String aliasName) {
		try (KmsClient kms = kmsClient()) {
			String keyId = "";
			String kmsAliasName = "alias/" + aliasName;
			// Check if alias already exists
			ListAliasesResponse aliases = kms.listAliases();

			String existingKeyId = aliases.aliases().stream().filter(a -> kmsAliasName.equals(a.aliasName()))
					.map(AliasListEntry::targetKeyId).findFirst().orElse(null);

			if (existingKeyId != null) {
				keyId = existingKeyId;
				return "Existing KMS Key found: " + keyId;
			} else {
				// Create new KMS key
				CreateKeyResponse keyResponse = kms.createKey(CreateKeyRequest.builder()
						.description("Spring Boot generated key for dynamic encryption/decryption")
						.keyUsage(KeyUsageType.ENCRYPT_DECRYPT).build());

				keyId = keyResponse.keyMetadata().keyId();
				System.out.println("🔑 Created new KMS Key: " + keyId);

				// Create alias for easier lookup
				kms.createAlias(CreateAliasRequest.builder().aliasName(kmsAliasName).targetKeyId(keyId).build());
				System.out.println("Alias created: " + aliasName);
				return "KMS key created successfully with KeyId: " + keyId;
			}
		}

	}
}
