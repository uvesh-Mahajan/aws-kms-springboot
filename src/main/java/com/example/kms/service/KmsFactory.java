package com.example.kms.service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;

@Component
public class KmsFactory {
	

	private final Map<String,KmsKeyOperationsService> services;
	private final Map<String,KmsKeyOperationsService> servicesMap= new ConcurrentHashMap<>();
    
    
    public KmsFactory(Map<String, KmsKeyOperationsService> services) {
        this.services = services;
    }
    
    
    @PostConstruct
    public void init() {
    	servicesMap.putAll(services);
        System.out.println("Factory initialized with handlers: " + servicesMap.keySet());
    }

    public KmsKeyOperationsService getService(String type) {
    	KmsKeyOperationsService service = servicesMap.get(type);
        if (service == null) {
            throw new IllegalArgumentException("Invalid notification type: " + type);
        }
        return service;
    }

}
