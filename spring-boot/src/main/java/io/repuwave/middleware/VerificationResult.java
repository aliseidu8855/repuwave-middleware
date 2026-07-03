package io.repuwave.middleware;

/**
 * Verification result from the Repuwave API.
 */
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
