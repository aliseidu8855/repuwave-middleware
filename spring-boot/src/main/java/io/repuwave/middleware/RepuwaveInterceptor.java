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
 * Forwards the agent's signature to GET /v1/verify/, which verifies it
 * server-side. This previously trusted a client-supplied X-Repuwave-UAID header
 * and verified nothing, so anyone who knew a UAID passed -- and UAIDs are
 * public, listed in the key directory.
 *
 * The body hash is taken from an X-Repuwave-Body-Hash header if the caller
 * supplies one. This interceptor does not compute it: reading the body here
 * would consume the request stream before the application sees it. For requests
 * with a body, compute the hash in a ContentCachingRequestWrapper filter ahead
 * of this interceptor, or use one of the application-level middlewares.
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
            // Forward the agent's own proof. Without it the server refuses,
            // and with it the server -- not this interceptor -- is what
            // establishes that the caller really is this agent. That matters:
            // the UAID header alone is attacker-controlled, and UAIDs are
            // public, so trusting it was the original bug here.
            String signature = request.getHeader("X-Repuwave-Signature");
            String timestamp = request.getHeader("X-Repuwave-Timestamp");
            String bodyHash = request.getHeader("X-Repuwave-Body-Hash");

            VerificationResult result = client.verify(
                    uaid, signature, timestamp, bodyHash
            );

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
            // Failure mode is a deliberate, configurable choice -- and it
            // defaults to closed. It used to be an unconditional fail-open
            // described only in the comment on this line.
            //
            // Since 21 Sep 2026 /v1/verify/ requires the agent's signature, so
            // an unsigned request lands here with a 401. Failing open therefore
            // meant the entire guard could be bypassed by omitting one header,
            // which is not an outage policy, it is an open door.
            log.error("Repuwave verification error for {}: {}", uaid, e.getMessage());

            if (config.getFailureMode() == RepuwaveConfig.FailureMode.OPEN) {
                return true;
            }

            // 502, not 402. The agent is not untrusted -- we could not find
            // out. Telling its developer to improve their reputation when the
            // gate is broken sends them to fix the wrong thing.
            response.setStatus(502);
            response.setContentType("application/json");
            response.getWriter().write(objectMapper.writeValueAsString(
                java.util.Map.of(
                    "error", "Verification Unavailable",
                    "message", "Could not verify agent reputation. This is a problem at the gateway, not with your agent."
                )
            ));
            return false;
        }
    }
}
