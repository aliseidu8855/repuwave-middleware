package io.repuwave.middleware;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The response this package must be able to read.
 *
 * WHY THIS EXISTS
 * ---------------
 * VerificationResult declared four components and RepuwaveClient deserialises
 * with a plain `new ObjectMapper()` -- not Spring Boot's auto-configured one,
 * so FAIL_ON_UNKNOWN_PROPERTIES was enabled. The real /v1/verify/ response
 * carries eight fields plus dimensions and attestation, so every successful
 * 200 threw UnrecognizedPropertyException. The interceptor caught it and failed
 * open, which means this guard had never blocked an agent on its score.
 *
 * The CI job for this package is `mvn compile`. A deserialisation failure is a
 * runtime event, so compiling proved nothing. This is the test that would have.
 *
 * The payload below is the shape declared by VerifyResponseSerializer in
 * repuwave-core (apps/events/serializers.py).
 */
class VerificationResultTest {

    private static final String REAL_RESPONSE = """
        {
          "verified": true,
          "score": 82.4,
          "status": "ACTIVE",
          "uaid": "550e8400-e29b-41d4-a716-446655440000",
          "public_key": "7b8230afd82141952205f3409a578872aa66186b27aafdbdd53ea73bd183fa6d",
          "is_pro_tier": false,
          "total_events": 42,
          "unique_reporters": 7,
          "requested_dimension": "RELIABILITY",
          "dimensions": [
            {"dimension": "RELIABILITY", "score": 81.0, "confidence": 0.9, "rules_version": "1.0.0"}
          ],
          "attestation": {"kid": "abc", "sig": "def", "issued_at": 1758461400}
        }
        """;

    @Test
    void deserialisesTheResponseTheServerActuallySends() throws Exception {
        ObjectMapper mapper = new ObjectMapper();

        VerificationResult result = mapper.readValue(REAL_RESPONSE, VerificationResult.class);

        assertTrue(result.verified());
        assertEquals(82.4, result.score(), 0.001);
        assertEquals("ACTIVE", result.status());
        assertEquals("550e8400-e29b-41d4-a716-446655440000", result.uaid());
    }

    @Test
    void scoreThresholdStillApplies() throws Exception {
        VerificationResult result =
            new ObjectMapper().readValue(REAL_RESPONSE, VerificationResult.class);

        assertTrue(result.meetsMinimum(70));
        assertFalse(result.meetsMinimum(90));
    }

    @Test
    void anUnverifiedAgentNeverMeetsAThreshold() {
        // Guards meetsMinimum's `verified &&`: a high score on an unverified
        // response must not pass.
        VerificationResult result = new VerificationResult(false, 99.0, "BURNED", "u");

        assertFalse(result.meetsMinimum(1));
    }
}
