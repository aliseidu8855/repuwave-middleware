package io.repuwave.middleware;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for Repuwave middleware.
 *
 * Usage in application.yml:
 *   repuwave:
 *     api-url: https://api.repuwave.io/v1
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

    private String apiUrl = "https://api.repuwave.io/v1";
    private String apiKey;
    private int minimumScore = 50;
    private String uaidHeader = "X-Repuwave-UAID";
    private EnforceMode enforceMode = EnforceMode.ENFORCE;
    private String signupUrl = "https://repuwave.fasolink.app";

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

    public String getSignupUrl() { return signupUrl; }
    public void setSignupUrl(String signupUrl) { this.signupUrl = signupUrl; }
}
