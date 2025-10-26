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
     * SECURITY: Prevents brute-force attacks on authentication endpoints
     */
    public Bucket getLoginBucket(String clientId) {
        return buckets.computeIfAbsent("login:" + clientId, this::createLoginBucket);
    }

    /**
     * Get or create a bucket for transfer operations (10 requests per minute)
     * SECURITY: Prevents abuse of financial transfer operations
     */
    public Bucket getTransferBucket(String clientId) {
        return buckets.computeIfAbsent("transfer:" + clientId, this::createTransferBucket);
    }

    /**
     * Get or create a bucket for general API operations (30 requests per minute)
     * SECURITY: Prevents general API abuse
     */
    public Bucket getGeneralBucket(String clientId) {
        return buckets.computeIfAbsent("general:" + clientId, this::createGeneralBucket);
    }

    /**
     * Create bucket for login attempts - 5 requests per minute
     */
    private Bucket createLoginBucket(String key) {
        Bandwidth limit = Bandwidth.classic(5, Refill.intervally(5, Duration.ofMinutes(1)));
        return Bucket.builder()
                .addLimit(limit)
                .build();
    }

    /**
     * Create bucket for transfer operations - 10 requests per minute
     */
    private Bucket createTransferBucket(String key) {
        Bandwidth limit = Bandwidth.classic(10, Refill.intervally(10, Duration.ofMinutes(1)));
        return Bucket.builder()
                .addLimit(limit)
                .build();
    }

    /**
     * Create bucket for general API operations - 30 requests per minute
     */
    private Bucket createGeneralBucket(String key) {
        Bandwidth limit = Bandwidth.classic(30, Refill.intervally(30, Duration.ofMinutes(1)));
        return Bucket.builder()
                .addLimit(limit)
                .build();
    }

    /**
     * Check if request is allowed for login operations
     */
    public boolean isLoginAllowed(String clientId) {
        return getLoginBucket(clientId).tryConsume(1);
    }

    /**
     * Check if request is allowed for transfer operations
     */
    public boolean isTransferAllowed(String clientId) {
        return getTransferBucket(clientId).tryConsume(1);
    }

    /**
     * Check if request is allowed for general operations
     */
    public boolean isGeneralAllowed(String clientId) {
        return getGeneralBucket(clientId).tryConsume(1);
    }
}