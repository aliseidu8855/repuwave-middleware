package io.repuwave.middleware;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for Repuwave middleware.
 *
 * Usage in application.yml:
 *   repuwave:
 *     api-url: https://repuwave.fasolink.app/v1
 *     api-key: your-service-api-key
 *     minimum-score: 50
 *     uaid-header: X-Repuwave-UAID
 */
@ConfigurationProperties(prefix = "repuwave")
public class RepuwaveConfig {

    public enum EnforceMode {
        ENFORCE,
        AUDIT
    }

    private String apiUrl = "https://repuwave.fasolink.app/v1";
    private String apiKey;
    private int minimumScore = 50;
    private String uaidHeader = "X-Repuwave-UAID";
    private EnforceMode enforceMode = EnforceMode.ENFORCE;
    private String signupUrl = "https://repuwave.fasolink.app";

    /**
     * What to do when Repuwave itself cannot be reached or answers an error.
     *
     * Defaults to CLOSED, matching the nginx Lua gate, and changed from an
     * unconditional fail-open that was only described in a code comment.
     *
     * The default mattered more after 21 Sep 2026, when /v1/verify/ began
     * requiring the agent's signature. Before that, this path was reached only
     * during an outage. After it, an ordinary unsigned request produces a 401 --
     * so fail-open turned "the API is down" into "anyone who omits one header is
     * admitted", which is the whole guard bypassed with a single edit to a curl
     * command.
     */
    public enum FailureMode {
        CLOSED,
        OPEN
    }

    private FailureMode failureMode = FailureMode.CLOSED;

    public String getApiUrl() { return apiUrl; }
    public void setApiUrl(String apiUrl) { this.apiUrl = apiUrl; }

    public String getApiKey() { return apiKey; }
    public void setApiKey(String apiKey) { this.apiKey = apiKey; }

    public int getMinimumScore() { return minimumScore; }
    public void setMinimumScore(int minimumScore) { this.minimumScore = minimumScore; }

    public String getUaidHeader() { return uaidHeader; }
    public void setUaidHeader(String uaidHeader) { this.uaidHeader = uaidHeader; }

    public EnforceMode getEnforceMode() { return enforceMode; }
    public void setEnforceMode(EnforceMode enforceMode) { this.enforceMode = enforceMode; }

    public FailureMode getFailureMode() { return failureMode; }
    public void setFailureMode(FailureMode failureMode) { this.failureMode = failureMode; }

    public String getSignupUrl() { return signupUrl; }
    public void setSignupUrl(String signupUrl) { this.signupUrl = signupUrl; }
}
