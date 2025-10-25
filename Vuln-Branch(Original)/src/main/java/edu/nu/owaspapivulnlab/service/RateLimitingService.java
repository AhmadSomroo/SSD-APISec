package edu.nu.owaspapivulnlab.service;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

/**
 * SECURITY FIX: Rate limiting service to prevent abuse and brute-force attacks
 * FIXED: API4 Lack of Resources & Rate Limiting - Implements configurable rate limits
 */
@Service
public class RateLimitingService {
    
    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();
    
    /**
     * Get or create a bucket for login attempts (5 requests per minute)
     */
    public Bucket getLoginBucket(String clientId) {
        return buckets.computeIfAbsent("login:" + clientId, this::createLoginBucket);
    }
    
    /**
     * Get or create a bucket for transfer operations (10 requests per minute)
     */
    public Bucket getTransferBucket(String clientId) {
        return buckets.computeIfAbsent("transfer:" + clientId, this::createTransferBucket);
    }
    
    /**
     * Get or create a bucket for general API operations (30 requests per minute)
     */
    public Bucket getGeneralBucket(String clientId) {
        return buckets.computeIfAbsent("general:" + clientId, this::createGeneralBucket);
    }
    
    /**
     * Create bucket for login attempts - 5 requests per minute
     * SECURITY: Prevents brute-force password attacks
     */
    private Bucket createLoginBucket(String key) {
        Bandwidth limit = Bandwidth.classic(5, Refill.intervally(5, Duration.ofMinutes(1)));
        return Bucket.builder()
                .addLimit(limit)
                .build();
    }
    
    /**
     * Create bucket for transfer operations - 10 requests per minute
     * SECURITY: Prevents rapid-fire financial transactions
     */
    private Bucket createTransferBucket(String key) {
        Bandwidth limit = Bandwidth.classic(10, Refill.intervally(10, Duration.ofMinutes(1)));
        return Bucket.builder()
                .addLimit(limit)
                .build();
    }
    
    /**
     * Create bucket for general API operations - 30 requests per minute
     * SECURITY: Prevents API abuse and DoS attacks
     */
    private Bucket createGeneralBucket(String key) {
        Bandwidth limit = Bandwidth.classic(30, Refill.intervally(30, Duration.ofMinutes(1)));
        return Bucket.builder()
                .addLimit(limit)
                .build();
    }
    
    /**
     * Check if request is allowed and consume a token
     */
    public boolean isAllowed(Bucket bucket) {
        return bucket.tryConsume(1);
    }
    
    /**
     * Get available tokens in bucket (for rate limit headers)
     */
    public long getAvailableTokens(Bucket bucket) {
        return bucket.getAvailableTokens();
    }
    
    /**
     * Get rate limit information for a specific bucket type
     */
    public RateLimitInfo getRateLimitInfo(String clientId, String endpointType) {
        Bucket bucket = getBucketForType(clientId, endpointType);
        if (bucket == null) {
            return null;
        }
        
        return new RateLimitInfo(
            bucket.getAvailableTokens(),
            getLimitForType(endpointType),
            System.currentTimeMillis() + 60000 // Reset in 1 minute
        );
    }
    
    /**
     * Get bucket for specific endpoint type
     */
    private Bucket getBucketForType(String clientId, String endpointType) {
        switch (endpointType.toLowerCase()) {
            case "login":
                return getLoginBucket(clientId);
            case "transfer":
                return getTransferBucket(clientId);
            case "general":
                return getGeneralBucket(clientId);
            default:
                return getGeneralBucket(clientId);
        }
    }
    
    /**
     * Get limit for specific endpoint type
     */
    private int getLimitForType(String endpointType) {
        switch (endpointType.toLowerCase()) {
            case "login":
                return 5;
            case "transfer":
                return 10;
            case "general":
                return 30;
            default:
                return 30;
        }
    }
    
    /**
     * Rate limit information container
     */
    public static class RateLimitInfo {
        private final long remaining;
        private final int limit;
        private final long resetTime;
        
        public RateLimitInfo(long remaining, int limit, long resetTime) {
            this.remaining = remaining;
            this.limit = limit;
            this.resetTime = resetTime;
        }
        
        public long getRemaining() { return remaining; }
        public int getLimit() { return limit; }
        public long getResetTime() { return resetTime; }
    }
}