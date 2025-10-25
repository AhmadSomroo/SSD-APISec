package edu.nu.owaspapivulnlab.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.nu.owaspapivulnlab.service.RateLimitingService;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * SECURITY FIX: Rate limiting filter to prevent abuse and brute-force attacks
 * FIXED: API4 Lack of Resources & Rate Limiting - Applies rate limits to critical endpoints
 */
@Component
public class RateLimitingFilter extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(RateLimitingFilter.class);
    
    private final RateLimitingService rateLimitingService;
    private final ObjectMapper objectMapper;
    
    public RateLimitingFilter(RateLimitingService rateLimitingService) {
        this.rateLimitingService = rateLimitingService;
        this.objectMapper = new ObjectMapper();
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        String clientId = getClientId(request);
        String requestURI = request.getRequestURI();
        String method = request.getMethod();
        
        Bucket bucket = getBucketForRequest(clientId, requestURI, method);
        
        if (bucket != null) {
            if (!rateLimitingService.isAllowed(bucket)) {
                // SECURITY FIX: Return HTTP 429 when rate limit exceeded
                handleRateLimitExceeded(response, bucket);
                return;
            }
            
            // Add rate limit headers for client awareness
            addRateLimitHeaders(response, bucket);
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * Get appropriate bucket based on request type
     */
    private Bucket getBucketForRequest(String clientId, String requestURI, String method) {
        // SECURITY: Different rate limits for different endpoint types
        if (requestURI.contains("/auth/login")) {
            return rateLimitingService.getLoginBucket(clientId);
        } else if (requestURI.contains("/transfer") && "POST".equals(method)) {
            return rateLimitingService.getTransferBucket(clientId);
        } else if (requestURI.startsWith("/api/")) {
            return rateLimitingService.getGeneralBucket(clientId);
        }
        
        return null; // No rate limiting for non-API endpoints
    }
    
    /**
     * Get client identifier (IP address for now, could be enhanced with user ID)
     */
    private String getClientId(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
    
    /**
     * Handle rate limit exceeded - return HTTP 429
     */
    private void handleRateLimitExceeded(HttpServletResponse response, Bucket bucket) throws IOException {
        response.setStatus(HttpServletResponse.SC_TOO_MANY_REQUESTS); // 429 Too Many Requests
        response.setContentType("application/json");
        
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "Rate limit exceeded");
        errorResponse.put("message", "Too many requests. Please try again later.");
        errorResponse.put("availableTokens", rateLimitingService.getAvailableTokens(bucket));
        errorResponse.put("retryAfter", "60"); // Retry after 60 seconds
        
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
        
        // SECURITY: Log rate limit violations for monitoring
        logger.warn("Rate limit exceeded for bucket: {}", bucket);
    }
    
    /**
     * Add rate limit headers to response for client awareness
     */
    private void addRateLimitHeaders(HttpServletResponse response, Bucket bucket) {
        long availableTokens = rateLimitingService.getAvailableTokens(bucket);
        
        // SECURITY FIX: Add comprehensive rate limit headers for client awareness
        response.setHeader("X-RateLimit-Remaining", String.valueOf(availableTokens));
        response.setHeader("X-RateLimit-Limit", "30"); // Default limit for general API
        response.setHeader("X-RateLimit-Reset", String.valueOf(System.currentTimeMillis() + 60000)); // Reset in 1 minute
        response.setHeader("Retry-After", "60"); // Retry after 60 seconds if rate limited
    }
    
    /**
     * Get endpoint type for rate limiting
     */
    private String getEndpointType(String requestURI, String method) {
        if (requestURI.contains("/auth/login")) {
            return "login";
        } else if (requestURI.contains("/transfer") && "POST".equals(method)) {
            return "transfer";
        } else if (requestURI.startsWith("/api/")) {
            return "general";
        }
        return "general";
    }
}