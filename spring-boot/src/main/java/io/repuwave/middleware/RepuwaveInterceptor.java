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
