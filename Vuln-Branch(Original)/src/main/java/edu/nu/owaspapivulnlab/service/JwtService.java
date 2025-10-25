package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.Date;
import java.util.Map;

/**
 * SECURITY FIX: Enhanced JWT service with environment-based configuration
 * FIXED: API8 Weak Authentication - Implements secure JWT token management
 */
@Service
public class JwtService {

    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.ttl-seconds}")
    private long ttlSeconds;

    // SECURITY FIX: Define expected issuer and audience for JWT validation
    private static final String ISSUER = "owasp-api-vuln-lab";
    private static final String AUDIENCE = "api-users";
    
    // SECURITY FIX: Maximum token lifetime validation (15 minutes = 900 seconds)
    private static final long MAX_TTL_SECONDS = 900;
    
    // SECURITY FIX: Validate configuration after dependency injection
    @PostConstruct
    public void validateConfiguration() {
        validateJwtConfiguration();
    }
    
    /**
     * SECURITY FIX: Validate JWT configuration for security requirements
     */
    private void validateJwtConfiguration() {
        // SECURITY FIX: Ensure secret key is strong enough (minimum 256 bits = 32 characters)
        if (secret == null || secret.length() < 32) {
            throw new IllegalStateException("JWT secret must be at least 256 bits (32 characters) for security");
        }
        
        // SECURITY FIX: Enforce maximum token lifetime of 15 minutes
        if (ttlSeconds > MAX_TTL_SECONDS) {
            throw new IllegalStateException("JWT token lifetime cannot exceed 15 minutes (900 seconds) for security");
        }
        
        // SECURITY FIX: Warn if using default secret in production
        if (secret.equals("mySecretKeyThatIsAtLeast256BitsLongForHS256AlgorithmToWorkProperlyInProduction")) {
            System.err.println("WARNING: Using default JWT secret. Set JWT_SECRET environment variable for production!");
        }
    }

    /**
     * SECURITY FIX: Issue JWT token with enhanced security claims
     * FIXED: API8 Weak Authentication - Includes issuer, audience, and short TTL
     */
    public String issue(String subject, Map<String, Object> claims) {
        if (subject == null || subject.trim().isEmpty()) {
            throw new IllegalArgumentException("JWT subject cannot be null or empty");
        }
        
        long now = System.currentTimeMillis();
        long expirationTime = now + (ttlSeconds * 1000);
        
        // SECURITY FIX: Create JWT with all required security claims
        return Jwts.builder()
                .setSubject(subject)
                .addClaims(claims)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(expirationTime))
                .setIssuer(ISSUER)        // SECURITY FIX: Include issuer claim
                .setAudience(AUDIENCE)    // SECURITY FIX: Include audience claim
                .signWith(SignatureAlgorithm.HS256, secret.getBytes())
                .compact();
    }
    
    /**
     * SECURITY FIX: Get current token lifetime for monitoring
     */
    public long getTokenLifetimeSeconds() {
        return ttlSeconds;
    }
    
    /**
     * SECURITY FIX: Check if current configuration is secure
     */
    public boolean isConfigurationSecure() {
        return secret != null && secret.length() >= 32 && ttlSeconds <= MAX_TTL_SECONDS;
    }
}
