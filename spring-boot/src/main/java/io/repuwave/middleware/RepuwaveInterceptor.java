package io.repuwave.middleware;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.HandlerInterceptor;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;

/**
 * Spring Boot HandlerInterceptor for Repuwave reputation gating.
 *
 * KNOWN BROKEN -- DO NOT DEPLOY. See the repository README.
 *
 * Two problems. This trusts a client-supplied UAID header and never verifies a
 * signature, so anyone who knows a UAID passes -- and UAIDs are public, listed
 * in the key directory. And since GET /v1/verify/{uaid}/ began checking
 * signatures it forwards none, so every call now returns 401.
 *
 * The fix is to forward X-Repuwave-Signature, X-Repuwave-Timestamp and the
 * body's sha256, as the Python, Express and nginx gates now do. It is not done
 * here because there is no Java toolchain in this repository's CI, and shipping
 * unverified code into a security path is how the first problem arrived.
 *
 * Verifies the agent's UAID against the Repuwave API and blocks
 * requests from agents that do not meet the minimum score.
 *
 * Usage:
 *   @Configuration
 *   public class WebConfig implements WebMvcConfigurer {
 *       @Override
 *       public void addInterceptors(InterceptorRegistry registry) {
 *           registry.addInterceptor(new RepuwaveInterceptor(config))
 *                   .addPathPatterns("/api/**");
 *       }
 *   }
 */
public class RepuwaveInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(RepuwaveInterceptor.class);

    private final RepuwaveClient client;
    private final RepuwaveConfig config;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public RepuwaveInterceptor(RepuwaveConfig config) {
        this.config = config;
        this.client = new RepuwaveClient(config);
    }

    @Override
    public boolean preHandle(
            HttpServletRequest request,
            HttpServletResponse response,
            Object handler
    ) throws Exception {

        String uaid = request.getHeader(config.getUaidHeader());
        
        Map<String, Object> viralResponse = Map.of(
            "error", "Untrusted Agent",
            "message", "This endpoint requires a Repuwave Trust Score of " + config.getMinimumScore() + "+. Get verified at " + config.getSignupUrl()
        );

        if (uaid == null || uaid.isBlank()) {
            if (config.getEnforceMode() == RepuwaveConfig.EnforceMode.ENFORCE) {
                response.setStatus(402);
                response.setContentType("application/json");
                response.getWriter().write(objectMapper.writeValueAsString(viralResponse));
                return false;
            } else {
                // Audit mode: let it pass through
                return true;
            }
        }

        try {
            VerificationResult result = client.verify(uaid);

            // Attach to request attributes for downstream use
            request.setAttribute("repuwave.result", result);
            request.setAttribute("repuwave.score", result.score());
            request.setAttribute("repuwave.uaid", result.uaid());

            if (!result.meetsMinimum(config.getMinimumScore())) {
                log.warn("Agent {} rejected: score={}, minimum={}",
                        uaid, result.score(), config.getMinimumScore());

                if (config.getEnforceMode() == RepuwaveConfig.EnforceMode.ENFORCE) {
                    response.setStatus(402);
                    response.setContentType("application/json");
                    response.getWriter().write(objectMapper.writeValueAsString(viralResponse));
                    return false;
                }
            }

            log.debug("Agent {} verified: score={}", uaid, result.score());
            return true;

        } catch (Exception e) {
            // Fail-open: log error but allow request through
            log.error("Repuwave verification error for {}: {}", uaid, e.getMessage());
            return true;
        }
    }
}
