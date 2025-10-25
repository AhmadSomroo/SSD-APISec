package edu.nu.owaspapivulnlab.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.nu.owaspapivulnlab.service.RateLimitingService;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
        response.setStatus(429); // Too Many Requests
        response.setContentType("application/json");
        
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "Rate limit exceeded");
        errorResponse.put("message", "Too many requests. Please try again later.");
        errorResponse.put("availableTokens", rateLimitingService.getAvailableTokens(bucket));
        
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
        
        // SECURITY: Log rate limit violations for monitoring
        logger.warn("Rate limit exceeded for client: " + getClientId(null));
    }
    
    /**
     * Add rate limit headers to response
     */
    private void addRateLimitHeaders(HttpServletResponse response, Bucket bucket) {
        long availableTokens = rateLimitingService.getAvailableTokens(bucket);
        response.setHeader("X-RateLimit-Remaining", String.valueOf(availableTokens));
    }
}