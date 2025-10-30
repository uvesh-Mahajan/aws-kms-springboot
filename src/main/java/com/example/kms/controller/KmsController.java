package com.example.kms.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.kms.service.KmsFactory;
import com.example.kms.service.KmsKeyOperationsService;

@RestController
@RequestMapping("/kms")
public class KmsController {

	@Autowired
	public KmsFactory kmsFactory;

	@Value("${aws.kms.keyCreationProcess}")
	private String keyCreationProcess;

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
}
