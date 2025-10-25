package edu.nu.owaspapivulnlab;

import edu.nu.owaspapivulnlab.service.InputValidationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SECURITY FIX: Unit tests for InputValidationService
 * FIXED: API9 Improper Assets Management - Tests comprehensive input validation
 */
@SpringBootTest
@TestPropertySource(properties = {
    "app.jwt.secret=testSecretKeyThatIsAtLeast256BitsLongForHS256AlgorithmToWorkProperlyInProduction",
    "app.jwt.ttl-seconds=900"
})
public class InputValidationServiceTest {

    private InputValidationService inputValidationService;

    @BeforeEach
    void setUp() {
        inputValidationService = new InputValidationService();
    }

    @Test
    void testValidateTransferAmount_ValidAmount() {
        // Test valid transfer amounts
        assertTrue(inputValidationService.validateTransferAmount(10.50).isValid());
        assertTrue(inputValidationService.validateTransferAmount(0.01).isValid());
        assertTrue(inputValidationService.validateTransferAmount(10000.00).isValid());
    }

    @Test
    void testValidateTransferAmount_InvalidAmount() {
        // Test invalid transfer amounts
        assertFalse(inputValidationService.validateTransferAmount(null).isValid());
        assertFalse(inputValidationService.validateTransferAmount(0.0).isValid());
        assertFalse(inputValidationService.validateTransferAmount(-10.0).isValid());
        assertFalse(inputValidationService.validateTransferAmount(0.005).isValid());
        assertFalse(inputValidationService.validateTransferAmount(10001.0).isValid());
        assertFalse(inputValidationService.validateTransferAmount(Double.NaN).isValid());
        assertFalse(inputValidationService.validateTransferAmount(Double.POSITIVE_INFINITY).isValid());
    }

    @Test
    void testValidateUsername_ValidUsernames() {
        // Test valid usernames
        InputValidationService.ValidationResult result1 = inputValidationService.validateUsername("testuser");
        assertTrue(result1.isValid());
        assertEquals("testuser", result1.getSanitizedValue());

        InputValidationService.ValidationResult result2 = inputValidationService.validateUsername("user123");
        assertTrue(result2.isValid());
        assertEquals("user123", result2.getSanitizedValue());

        InputValidationService.ValidationResult result3 = inputValidationService.validateUsername("user_name");
        assertTrue(result3.isValid());
        assertEquals("user_name", result3.getSanitizedValue());

        InputValidationService.ValidationResult result4 = inputValidationService.validateUsername("user-name");
        assertTrue(result4.isValid());
        assertEquals("user-name", result4.getSanitizedValue());
    }

    @Test
    void testValidateUsername_InvalidUsernames() {
        // Test invalid usernames
        assertFalse(inputValidationService.validateUsername(null).isValid());
        assertFalse(inputValidationService.validateUsername("").isValid());
        assertFalse(inputValidationService.validateUsername("ab").isValid()); // Too short
        assertFalse(inputValidationService.validateUsername("user@domain").isValid()); // Invalid character
        assertFalse(inputValidationService.validateUsername("user name").isValid()); // Space not allowed
        assertFalse(inputValidationService.validateUsername("user<script>").isValid()); // XSS attempt
    }

    @Test
    void testValidateEmail_ValidEmails() {
        // Test valid emails
        InputValidationService.ValidationResult result1 = inputValidationService.validateEmail("test@example.com");
        assertTrue(result1.isValid());
        assertEquals("test@example.com", result1.getSanitizedValue());

        InputValidationService.ValidationResult result2 = inputValidationService.validateEmail("user.name@domain.co.uk");
        assertTrue(result2.isValid());
        assertEquals("user.name@domain.co.uk", result2.getSanitizedValue());
    }

    @Test
    void testValidateEmail_InvalidEmails() {
        // Test invalid emails
        assertFalse(inputValidationService.validateEmail(null).isValid());
        assertFalse(inputValidationService.validateEmail("").isValid());
        assertFalse(inputValidationService.validateEmail("invalid-email").isValid());
        assertFalse(inputValidationService.validateEmail("@domain.com").isValid());
        assertFalse(inputValidationService.validateEmail("user@").isValid());
    }

    @Test
    void testValidatePassword_ValidPasswords() {
        // Test valid passwords
        assertTrue(inputValidationService.validatePassword("password123").isValid());
        assertTrue(inputValidationService.validatePassword("123456").isValid());
        assertTrue(inputValidationService.validatePassword("abcdef").isValid());
    }

    @Test
    void testValidatePassword_InvalidPasswords() {
        // Test invalid passwords
        assertFalse(inputValidationService.validatePassword(null).isValid());
        assertFalse(inputValidationService.validatePassword("").isValid());
        assertFalse(inputValidationService.validatePassword("12345").isValid()); // Too short
    }

    @Test
    void testValidateSearchQuery_ValidQueries() {
        // Test valid search queries
        InputValidationService.ValidationResult result1 = inputValidationService.validateSearchQuery("test query");
        assertTrue(result1.isValid());
        assertEquals("test query", result1.getSanitizedValue());

        InputValidationService.ValidationResult result2 = inputValidationService.validateSearchQuery(null);
        assertTrue(result2.isValid());
        assertEquals("", result2.getSanitizedValue());
    }

    @Test
    void testValidateSearchQuery_InvalidQueries() {
        // Test invalid search queries (too long)
        String longQuery = "a".repeat(201); // Exceeds MAX_SEARCH_QUERY_LENGTH
        assertFalse(inputValidationService.validateSearchQuery(longQuery).isValid());
    }

    @Test
    void testValidateNumericId_ValidIds() {
        // Test valid numeric IDs
        assertTrue(inputValidationService.validateNumericId(1L).isValid());
        assertTrue(inputValidationService.validateNumericId(100L).isValid());
        assertTrue(inputValidationService.validateNumericId(Long.MAX_VALUE / 2).isValid());
    }

    @Test
    void testValidateNumericId_InvalidIds() {
        // Test invalid numeric IDs
        assertFalse(inputValidationService.validateNumericId(null).isValid());
        assertFalse(inputValidationService.validateNumericId(0L).isValid());
        assertFalse(inputValidationService.validateNumericId(-1L).isValid());
        assertFalse(inputValidationService.validateNumericId(Long.MAX_VALUE).isValid());
    }

    @Test
    void testSanitizeString_XSSPrevention() {
        // Test XSS prevention
        String maliciousInput = "<script>alert('xss')</script>";
        String sanitized = inputValidationService.sanitizeString(maliciousInput);
        assertFalse(sanitized.contains("<script>"));
        assertFalse(sanitized.contains("alert"));
    }

    @Test
    void testSanitizeString_SQLInjectionPrevention() {
        // Test SQL injection prevention
        String maliciousInput = "'; DROP TABLE users; --";
        String sanitized = inputValidationService.sanitizeString(maliciousInput);
        // The sanitization replaces DROP with [FILTERED]
        assertTrue(sanitized.contains("[FILTERED]"));
        assertFalse(sanitized.contains("DROP"));
    }

    @Test
    void testSanitizeString_SpecialCharacters() {
        // Test special character escaping
        String input = "test<>\"'&";
        String sanitized = inputValidationService.sanitizeString(input);
        
        // Check that special characters are properly escaped
        assertTrue(sanitized.contains("&lt;"));
        assertTrue(sanitized.contains("&gt;"));
        assertTrue(sanitized.contains("&quot;"));
        assertTrue(sanitized.contains("&#x27;"));
        assertTrue(sanitized.contains("&amp;"));
    }

    @Test
    void testValidateNumericRange_ValidRanges() {
        // Test valid numeric ranges
        assertTrue(inputValidationService.validateNumericRange(5, "test", 1, 10).isValid());
        assertTrue(inputValidationService.validateNumericRange(1, "test", 1, 10).isValid());
        assertTrue(inputValidationService.validateNumericRange(10, "test", 1, 10).isValid());
        assertTrue(inputValidationService.validateNumericRange(5, "test", null, 10).isValid());
        assertTrue(inputValidationService.validateNumericRange(5, "test", 1, null).isValid());
    }

    @Test
    void testValidateNumericRange_InvalidRanges() {
        // Test invalid numeric ranges
        assertFalse(inputValidationService.validateNumericRange(null, "test", 1, 10).isValid());
        assertFalse(inputValidationService.validateNumericRange(0, "test", 1, 10).isValid());
        assertFalse(inputValidationService.validateNumericRange(11, "test", 1, 10).isValid());
        assertFalse(inputValidationService.validateNumericRange(Double.NaN, "test", 1, 10).isValid());
        assertFalse(inputValidationService.validateNumericRange(Double.POSITIVE_INFINITY, "test", 1, 10).isValid());
    }

    @Test
    void testGetTransferLimits() {
        // Test transfer limit getters
        assertNotNull(inputValidationService.getMaxTransferLimit());
        assertNotNull(inputValidationService.getMinTransferLimit());
        assertEquals(10000.00, inputValidationService.getMaxTransferLimit().doubleValue());
        assertEquals(0.01, inputValidationService.getMinTransferLimit().doubleValue());
    }
}
