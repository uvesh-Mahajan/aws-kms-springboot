package com.example.kms.service;

import java.util.Map;

import com.nimbusds.jose.jwk.JWK;

import software.amazon.awssdk.services.kms.KmsClient;

public interface KmsKeyOperationsService {

	  public String encrypt(String plainText);
	  public String decrypt(String plainText);
	  public JWK jwkFromKms() throws Exception;
	  public KmsClient getKmsClient();
	  public Map<String, Object> getJwks() throws Exception;
	
}
