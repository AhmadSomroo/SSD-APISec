package edu.nu.owaspapivulnlab;

import edu.nu.owaspapivulnlab.service.RateLimitingService;
import io.github.bucket4j.Bucket;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SECURITY FIX: Unit tests for rate limiting service
 * FIXED: API4 Lack of Resources & Rate Limiting - Verifies rate limiting service functionality
 */
@SpringBootTest
@TestPropertySource(properties = {
    "app.jwt.secret=testSecretKeyThatIsAtLeast256BitsLongForHS256AlgorithmToWorkProperlyInProductionAndMore",
    "app.jwt.ttl-seconds=900"
})
public class RateLimitingServiceTest {

    @Autowired
    private RateLimitingService rateLimitingService;

    @Test
    public void testLoginBucketCreation() {
        // SECURITY FIX: Test login bucket creation and limits
        Bucket loginBucket = rateLimitingService.getLoginBucket("test-client");
        assertNotNull(loginBucket, "Login bucket should not be null");
        
        // Test that we can consume tokens
        assertTrue(rateLimitingService.isAllowed(loginBucket), "First request should be allowed");
        assertTrue(rateLimitingService.isAllowed(loginBucket), "Second request should be allowed");
        assertTrue(rateLimitingService.isAllowed(loginBucket), "Third request should be allowed");
        assertTrue(rateLimitingService.isAllowed(loginBucket), "Fourth request should be allowed");
        assertTrue(rateLimitingService.isAllowed(loginBucket), "Fifth request should be allowed");
        
        // SECURITY FIX: 6th request should be rate limited
        assertFalse(rateLimitingService.isAllowed(loginBucket), "Sixth request should be rate limited");
    }

    @Test
    public void testTransferBucketCreation() {
        // SECURITY FIX: Test transfer bucket creation and limits
        Bucket transferBucket = rateLimitingService.getTransferBucket("test-client");
        assertNotNull(transferBucket, "Transfer bucket should not be null");
        
        // Test that we can consume tokens (10 requests)
        for (int i = 0; i < 10; i++) {
            assertTrue(rateLimitingService.isAllowed(transferBucket), 
                "Request " + (i + 1) + " should be allowed");
        }
        
        // SECURITY FIX: 11th request should be rate limited
        assertFalse(rateLimitingService.isAllowed(transferBucket), 
            "11th request should be rate limited");
    }

    @Test
    public void testGeneralBucketCreation() {
        // SECURITY FIX: Test general bucket creation and limits
        Bucket generalBucket = rateLimitingService.getGeneralBucket("test-client");
        assertNotNull(generalBucket, "General bucket should not be null");
        
        // Test that we can consume tokens (30 requests)
        for (int i = 0; i < 30; i++) {
            assertTrue(rateLimitingService.isAllowed(generalBucket), 
                "Request " + (i + 1) + " should be allowed");
        }
        
        // SECURITY FIX: 31st request should be rate limited
        assertFalse(rateLimitingService.isAllowed(generalBucket), 
            "31st request should be rate limited");
    }

    @Test
    public void testAvailableTokens() {
        // SECURITY FIX: Test available tokens tracking
        Bucket loginBucket = rateLimitingService.getLoginBucket("test-client-2");
        
        // Initially should have 5 tokens
        assertEquals(5, rateLimitingService.getAvailableTokens(loginBucket), 
            "Should start with 5 available tokens");
        
        // Consume one token
        rateLimitingService.isAllowed(loginBucket);
        assertEquals(4, rateLimitingService.getAvailableTokens(loginBucket), 
            "Should have 4 available tokens after consuming 1");
        
        // Consume all tokens
        for (int i = 0; i < 4; i++) {
            rateLimitingService.isAllowed(loginBucket);
        }
        assertEquals(0, rateLimitingService.getAvailableTokens(loginBucket), 
            "Should have 0 available tokens after consuming all");
    }

    @Test
    public void testDifferentClientsHaveSeparateBuckets() {
        // SECURITY FIX: Test that different clients have separate rate limits
        Bucket client1Bucket = rateLimitingService.getLoginBucket("client-1");
        Bucket client2Bucket = rateLimitingService.getLoginBucket("client-2");
        
        // Exhaust client-1's rate limit
        for (int i = 0; i < 5; i++) {
            assertTrue(rateLimitingService.isAllowed(client1Bucket), 
                "Client-1 request " + (i + 1) + " should be allowed");
        }
        assertFalse(rateLimitingService.isAllowed(client1Bucket), 
            "Client-1 6th request should be rate limited");
        
        // Client-2 should still have full rate limit
        assertTrue(rateLimitingService.isAllowed(client2Bucket), 
            "Client-2 should still have available tokens");
    }

    @Test
    public void testRateLimitInfo() {
        // SECURITY FIX: Test rate limit information retrieval
        RateLimitingService.RateLimitInfo loginInfo = rateLimitingService.getRateLimitInfo("test-client", "login");
        assertNotNull(loginInfo, "Login rate limit info should not be null");
        assertEquals(5, loginInfo.getLimit(), "Login limit should be 5");
        assertTrue(loginInfo.getRemaining() >= 0, "Remaining tokens should be non-negative");
        
        RateLimitingService.RateLimitInfo transferInfo = rateLimitingService.getRateLimitInfo("test-client", "transfer");
        assertNotNull(transferInfo, "Transfer rate limit info should not be null");
        assertEquals(10, transferInfo.getLimit(), "Transfer limit should be 10");
        
        RateLimitingService.RateLimitInfo generalInfo = rateLimitingService.getRateLimitInfo("test-client", "general");
        assertNotNull(generalInfo, "General rate limit info should not be null");
        assertEquals(30, generalInfo.getLimit(), "General limit should be 30");
    }

    @Test
    public void testBucketReuse() {
        // SECURITY FIX: Test that same client gets same bucket instance
        Bucket bucket1 = rateLimitingService.getLoginBucket("same-client");
        Bucket bucket2 = rateLimitingService.getLoginBucket("same-client");
        
        assertSame(bucket1, bucket2, "Same client should get same bucket instance");
        
        // Consume tokens from one bucket
        rateLimitingService.isAllowed(bucket1);
        
        // Other bucket should reflect the same state
        assertEquals(4, rateLimitingService.getAvailableTokens(bucket2), 
            "Both bucket references should reflect same state");
    }
}
