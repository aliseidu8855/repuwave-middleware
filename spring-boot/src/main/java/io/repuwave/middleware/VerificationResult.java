package io.repuwave.middleware;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Verification result from the Repuwave API.
 *
 * ignoreUnknown is load-bearing, not tidiness. RepuwaveClient builds a plain
 * `new ObjectMapper()`, which is NOT Spring Boot's auto-configured one and
 * therefore has FAIL_ON_UNKNOWN_PROPERTIES enabled. /v1/verify/ returns
 * public_key, is_pro_tier, total_events and unique_reporters as well as these
 * four, plus dimensions and attestation on most responses.
 *
 * So every successful 200 threw UnrecognizedPropertyException, which the
 * interceptor caught and failed open on. The guard admitted every agent at
 * every score, including BURNED, and had never blocked anything except a
 * request with no UAID header at all.
 *
 * Nothing caught it: the CI job for this package is `mvn compile`, and a
 * deserialisation failure is a runtime event.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record VerificationResult(
    boolean verified,
    double score,
    String status,
    String uaid
) {
    /**
     * Check if the score meets a minimum threshold.
     */
    public boolean meetsMinimum(int minimumScore) {
        return verified && score >= minimumScore;
    }
}
