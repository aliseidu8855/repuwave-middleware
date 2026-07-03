package io.repuwave.middleware;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * HTTP client for the Repuwave verify API with in-memory caching.
 */
public class RepuwaveClient {

    private final RepuwaveConfig config;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Map<String, CachedResult> cache = new ConcurrentHashMap<>();

    private static final long CACHE_TTL_MS = 300_000; // 5 minutes

    private record CachedResult(VerificationResult result, long expiresAt) {}

    public RepuwaveClient(RepuwaveConfig config) {
        this.config = config;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Verify an agent's reputation score.
     */
    public VerificationResult verify(String uaid) throws IOException, InterruptedException {
        // Check cache
        CachedResult cached = cache.get(uaid);
        if (cached != null && cached.expiresAt > System.currentTimeMillis()) {
            return cached.result;
        }

        // Call API
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(config.getApiUrl() + "/verify/" + uaid + "/"))
                .header("X-Service-API-Key", config.getApiKey())
                .header("Content-Type", "application/json")
                .GET()
                .timeout(Duration.ofSeconds(10))
                .build();

        HttpResponse<String> response = httpClient.send(
                request, HttpResponse.BodyHandlers.ofString()
        );

        if (response.statusCode() == 404) {
            return new VerificationResult(false, 0, "UNKNOWN", uaid);
        }

        if (response.statusCode() != 200) {
            throw new IOException(
                    "Repuwave API error: " + response.statusCode()
            );
        }

        VerificationResult result = objectMapper.readValue(
                response.body(), VerificationResult.class
        );

        // Cache result
        cache.put(uaid, new CachedResult(result, System.currentTimeMillis() + CACHE_TTL_MS));

        return result;
    }

    public void clearCache() {
        cache.clear();
    }
}
