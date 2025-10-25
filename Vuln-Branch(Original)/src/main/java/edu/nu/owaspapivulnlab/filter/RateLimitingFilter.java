package edu.nu.owaspapivulnlab.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.nu.owaspapivulnlab.service.RateLimitingService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * SECURITY FIX: Rate limiting filter to prevent abuse and brute-force attacks
 * FIXED: API4 Lack of Resources & Rate Limiting - Enforces rate limits on critical endpoints
 */
@Component
@Order(1) // Execute before security filters
public class RateLimitingFilter extends OncePerRequestFilter {

    private final RateLimitingService rateLimitingService;
    private final ObjectMapper objectMapper;

    public RateLimitingFilter(RateLimitingService rateLimitingService, ObjectMapper objectMapper) {
        this.rateLimitingService = rateLimitingService;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        String clientId = getClientId(request);
        String requestURI = request.getRequestURI();
        String method = request.getMethod();

        // Apply rate limiting based on endpoint type
        boolean allowed = true;
        String limitType = "general";

        if (isLoginEndpoint(requestURI, method)) {
            allowed = rateLimitingService.isLoginAllowed(clientId);
            limitType = "login";
        } else if (isTransferEndpoint(requestURI, method)) {
            allowed = rateLimitingService.isTransferAllowed(clientId);
            limitType = "transfer";
        } else if (isApiEndpoint(requestURI)) {
            allowed = rateLimitingService.isGeneralAllowed(clientId);
            limitType = "general";
        }

        if (!allowed) {
            handleRateLimitExceeded(response, limitType);
            return;
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Get client identifier for rate limiting (IP address)
     */
    private String getClientId(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    /**
     * Check if request is to login endpoint
     */
    private boolean isLoginEndpoint(String uri, String method) {
        return "POST".equals(method) && 
               (uri.equals("/api/auth/login") || uri.equals("/api/auth/login-form"));
    }

    /**
     * Check if request is to transfer endpoint
     */
    private boolean isTransferEndpoint(String uri, String method) {
        return "POST".equals(method) && uri.matches("/api/accounts/\\d+/transfer");
    }

    /**
     * Check if request is to API endpoint
     */
    private boolean isApiEndpoint(String uri) {
        return uri.startsWith("/api/");
    }

    /**
     * Handle rate limit exceeded - return HTTP 429
     */
    private void handleRateLimitExceeded(HttpServletResponse response, String limitType) throws IOException {
        response.setStatus(429); // HTTP 429 Too Many Requests
        response.setContentType("application/json");
        
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "Rate limit exceeded");
        errorResponse.put("message", "Too many requests for " + limitType + " operations");
        errorResponse.put("status", 429);
        
        // Add rate limit headers
        response.setHeader("X-RateLimit-Limit", getRateLimitForType(limitType));
        response.setHeader("X-RateLimit-Remaining", "0");
        response.setHeader("Retry-After", "60"); // Retry after 1 minute
        
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }

    /**
     * Get rate limit value for response headers
     */
    private String getRateLimitForType(String limitType) {
        switch (limitType) {
            case "login": return "5";
            case "transfer": return "10";
            case "general": return "30";
            default: return "30";
        }
    }
}