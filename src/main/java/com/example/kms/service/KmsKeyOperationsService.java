package com.example.kms.service;

public interface KmsKeyOperationsService {

	  public String encrypt(String plainText);
	  public String decrypt(String plainText);
	
}
