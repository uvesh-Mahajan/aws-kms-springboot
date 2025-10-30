package com.example.kms;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

import com.fasterxml.jackson.databind.ObjectMapper;

public class KmsPerformanceTest {

	private static final String ENCRYPT_URL = "http://localhost:8080/kms/encrypt";
	private static final String DECRYPT_URL = "http://localhost:8080/kms/decrypt";
	private static final int USER_COUNT = 1000;

	public static void main(String[] args) throws Exception {
		HttpClient client = HttpClient.newHttpClient();
		ExecutorService executor = Executors.newFixedThreadPool(USER_COUNT);
		ObjectMapper mapper = new ObjectMapper();

		System.out.println("========== KMS PARALLEL ENCRYPTION TEST ==========");
		List<Future<TestResult>> encryptionResults = runEncryptionTest(client, mapper, executor);

		printSummary("ENCRYPTION RESULTS", encryptionResults);

		System.out.println("\n========== KMS PARALLEL DECRYPTION TEST ==========");
		List<Future<TestResult>> decryptionResults = runDecryptionTest(client, mapper, executor);

		printSummary("DECRYPTION RESULTS", decryptionResults);

		executor.shutdown();
	}

	// ------------------- Encryption Test ---------------------
	private static List<Future<TestResult>> runEncryptionTest(HttpClient client, ObjectMapper mapper,
			ExecutorService executor) throws Exception {
		List<Callable<TestResult>> tasks = new ArrayList<>();

		for (int i = 0; i < USER_COUNT; i++) {
			final int userId = i;
			tasks.add(() -> {
				String text = "Hello from user " + userId;
				String body = mapper.writeValueAsString(Map.of("text", text));

				HttpRequest request = HttpRequest.newBuilder().uri(URI.create(ENCRYPT_URL))
						.header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body))
						.build();

				Instant start = Instant.now();
				HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
				Instant end = Instant.now();

				long duration = Duration.between(start, end).toMillis();
				String result = response.body();

				synchronized (System.out) {
					System.out.println("User " + userId + " | Time: " + duration + " ms | Response: " + result);
				}

				return new TestResult(duration, result);
			});
		}

		Instant totalStart = Instant.now();
		List<Future<TestResult>> results = executor.invokeAll(tasks);
		Instant totalEnd = Instant.now();

		long totalDuration = Duration.between(totalStart, totalEnd).toMillis();
		System.out.println("\nTotal time for "+USER_COUNT+" parallel encryptions: " + totalDuration + " ms\n");
		return results;
	}

	// ------------------- Decryption Test ---------------------
	private static List<Future<TestResult>> runDecryptionTest(HttpClient client, ObjectMapper mapper,
			ExecutorService executor) throws Exception {
		// First, get a sample cipher text
		String sampleCipher = encryptSampleText(client, mapper);

		List<Callable<TestResult>> tasks = new ArrayList<>();

		for (int i = 0; i < USER_COUNT; i++) {
			final int userId = i;
			tasks.add(() -> {
				String body = mapper.writeValueAsString(Map.of("cipher", sampleCipher));

				HttpRequest request = HttpRequest.newBuilder().uri(URI.create(DECRYPT_URL))
						.header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body))
						.build();

				Instant start = Instant.now();
				HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
				Instant end = Instant.now();

				long duration = Duration.between(start, end).toMillis();
				String result = response.body();

				synchronized (System.out) {
					System.out.println("User " + userId + " | Time: " + duration + " ms | Response: " + result);
				}

				return new TestResult(duration, result);
			});
		}

		Instant totalStart = Instant.now();
		List<Future<TestResult>> results = executor.invokeAll(tasks);
		Instant totalEnd = Instant.now();

		long totalDuration = Duration.between(totalStart, totalEnd).toMillis();
		System.out.println("\nTotal time for "+USER_COUNT+" parallel decryptions: " + totalDuration + " ms\n");
		return results;
	}

	// ------------------- Helpers ---------------------
	private static void printSummary(String title, List<Future<TestResult>> results) {
		System.out.println("\n==============================");
		System.out.println(title);
		System.out.println("==============================");

		double avgTime = results.stream().mapToLong(f -> {
			try {
				return f.get().timeTaken;
			} catch (Exception e) {
				return 0;
			}
		}).average().orElse(0);

		long maxTime = results.stream().mapToLong(f -> {
			try {
				return f.get().timeTaken;
			} catch (Exception e) {
				return 0;
			}
		}).max().orElse(0);

		System.out.println("Total Requests: " + results.size());
		System.out.println("Average Time per Request: " + avgTime + " ms");
		System.out.println("Max Time: " + maxTime + " ms\n");
	}

	private static String encryptSampleText(HttpClient client, ObjectMapper mapper) throws Exception {
		String body = mapper.writeValueAsString(Map.of("text", "SampleTextForDecryption"));
		HttpRequest request = HttpRequest.newBuilder().uri(URI.create(ENCRYPT_URL))
				.header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build();

		HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
		Map<String, String> result = mapper.readValue(response.body(), Map.class);
		return result.get("cipherText");
	}

	// ------------------- Inner Class ---------------------
	private static class TestResult {
		long timeTaken;
		String response;

		public TestResult(long timeTaken, String response) {
			this.timeTaken = timeTaken;
			this.response = response;
		}
	}
}
