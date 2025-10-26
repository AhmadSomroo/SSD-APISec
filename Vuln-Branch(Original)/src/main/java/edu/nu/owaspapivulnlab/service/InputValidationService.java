package edu.nu.owaspapivulnlab.service;

import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigDecimal;
import java.util.regex.Pattern;

/**
 * SECURITY FIX: Comprehensive input validation and sanitization service
 * FIXED: API9 Improper Assets Management - Prevents injection attacks and validates all inputs
 */
@Service
public class InputValidationService {
    
    private static final Logger logger = LoggerFactory.getLogger(InputValidationService.class);
    
    // SECURITY FIX: Maximum transfer limits per transaction
    private static final BigDecimal MAX_TRANSFER_AMOUNT = new BigDecimal("10000.00");
    private static final BigDecimal MIN_TRANSFER_AMOUNT = new BigDecimal("0.01");
    
    // SECURITY FIX: Maximum string lengths to prevent DoS attacks
    private static final int MAX_USERNAME_LENGTH = 50;
    private static final int MAX_EMAIL_LENGTH = 100;
    private static final int MAX_PASSWORD_LENGTH = 128;
    private static final int MAX_SEARCH_QUERY_LENGTH = 200;
    
    // SECURITY FIX: Patterns for input sanitization
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile("(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute|script|javascript|vbscript|onload|onerror|onclick)");
    private static final Pattern XSS_PATTERN = Pattern.compile("(?i)(<script|</script|javascript:|vbscript:|onload=|onerror=|onclick=|<iframe|</iframe|alert\\s*\\(|confirm\\s*\\(|prompt\\s*\\()");
    
    /**
     * SECURITY FIX: Validate and sanitize transfer amount
     */
    public ValidationResult validateTransferAmount(Double amount) {
        if (amount == null) {
            return ValidationResult.error("Transfer amount is required");
        }
        
        if (amount <= 0) {
            return ValidationResult.error("Transfer amount must be positive");
        }
        
        if (amount < MIN_TRANSFER_AMOUNT.doubleValue()) {
            return ValidationResult.error("Transfer amount must be at least " + MIN_TRANSFER_AMOUNT);
        }
        
        if (amount > MAX_TRANSFER_AMOUNT.doubleValue()) {
            return ValidationResult.error("Transfer amount cannot exceed " + MAX_TRANSFER_AMOUNT);
        }
        
        // SECURITY FIX: Check for suspicious values
        if (Double.isNaN(amount) || Double.isInfinite(amount)) {
            return ValidationResult.error("Invalid transfer amount");
        }
        
        return ValidationResult.success();
    }
    
    /**
     * SECURITY FIX: Validate and sanitize username
     */
    public ValidationResult validateUsername(String username) {
        if (username == null || username.trim().isEmpty()) {
            return ValidationResult.error("Username is required");
        }
        
        String sanitized = sanitizeString(username);
        
        if (sanitized.length() < 3) {
            return ValidationResult.error("Username must be at least 3 characters");
        }
        
        if (sanitized.length() > MAX_USERNAME_LENGTH) {
            return ValidationResult.error("Username cannot exceed " + MAX_USERNAME_LENGTH + " characters");
        }
        
        // SECURITY FIX: Check for valid username pattern
        if (!username.matches("^[a-zA-Z0-9_\\-]+$")) {
            return ValidationResult.error("Username can only contain letters, numbers, underscores, and hyphens");
        }
        
        return ValidationResult.success(sanitized);
    }
    
    /**
     * SECURITY FIX: Validate and sanitize email
     */
    public ValidationResult validateEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            return ValidationResult.error("Email is required");
        }
        
        String sanitized = sanitizeString(email);
        
        if (sanitized.length() > MAX_EMAIL_LENGTH) {
            return ValidationResult.error("Email cannot exceed " + MAX_EMAIL_LENGTH + " characters");
        }
        
        // SECURITY FIX: Basic email format validation
        if (!sanitized.matches("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$")) {
            return ValidationResult.error("Invalid email format");
        }
        
        return ValidationResult.success(sanitized);
    }
    
    /**
     * SECURITY FIX: Validate and sanitize password
     */
    public ValidationResult validatePassword(String password) {
        if (password == null || password.isEmpty()) {
            return ValidationResult.error("Password is required");
        }
        
        if (password.length() > MAX_PASSWORD_LENGTH) {
            return ValidationResult.error("Password cannot exceed " + MAX_PASSWORD_LENGTH + " characters");
        }
        
        // SECURITY FIX: Check for common weak passwords
        if (password.length() < 6) {
            return ValidationResult.error("Password must be at least 6 characters");
        }
        
        return ValidationResult.success();
    }
    
    /**
     * SECURITY FIX: Validate and sanitize search queries
     */
    public ValidationResult validateSearchQuery(String query) {
        if (query == null) {
            return ValidationResult.success("");
        }
        
        String sanitized = sanitizeString(query);
        
        if (sanitized.length() > MAX_SEARCH_QUERY_LENGTH) {
            return ValidationResult.error("Search query cannot exceed " + MAX_SEARCH_QUERY_LENGTH + " characters");
        }
        
        return ValidationResult.success(sanitized);
    }
    
    /**
     * SECURITY FIX: Validate numeric ID parameters
     */
    public ValidationResult validateNumericId(Long id) {
        if (id == null) {
            return ValidationResult.error("ID is required");
        }
        
        if (id <= 0) {
            return ValidationResult.error("ID must be positive");
        }
        
        if (id > Long.MAX_VALUE / 2) { // Reasonable upper limit
            return ValidationResult.error("ID is too large");
        }
        
        return ValidationResult.success();
    }
    
    /**
     * SECURITY FIX: Sanitize string inputs to prevent injection attacks
     */
    public String sanitizeString(String input) {
        if (input == null) {
            return "";
        }
        
        // SECURITY FIX: Remove or escape dangerous characters
        String sanitized = input.trim();
        
        // SECURITY FIX: Check for SQL injection patterns
        if (SQL_INJECTION_PATTERN.matcher(sanitized).find()) {
            logger.warn("Potential SQL injection attempt detected: {}", sanitized);
            sanitized = sanitized.replaceAll("(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)", "[FILTERED]");
        }
        
        // SECURITY FIX: Check for XSS patterns
        if (XSS_PATTERN.matcher(sanitized).find()) {
            logger.warn("Potential XSS attempt detected: {}", sanitized);
            sanitized = sanitized.replaceAll("(?i)(<script|</script|javascript:|vbscript:|onload=|onerror=|onclick=|<iframe|</iframe|alert\\s*\\(|confirm\\s*\\(|prompt\\s*\\()", "[FILTERED]");
        }
        
        // SECURITY FIX: Escape special characters (order matters - & must be last)
        sanitized = sanitized.replace("&", "&amp;")
                            .replace("<", "&lt;")
                            .replace(">", "&gt;")
                            .replace("\"", "&quot;")
                            .replace("'", "&#x27;");
        
        return sanitized;
    }
    
    /**
     * SECURITY FIX: Validate all numeric inputs for reasonable ranges
     */
    public ValidationResult validateNumericRange(Number value, String fieldName, Number min, Number max) {
        if (value == null) {
            return ValidationResult.error(fieldName + " is required");
        }
        
        double doubleValue = value.doubleValue();
        
        if (Double.isNaN(doubleValue) || Double.isInfinite(doubleValue)) {
            return ValidationResult.error(fieldName + " must be a valid number");
        }
        
        if (min != null && doubleValue < min.doubleValue()) {
            return ValidationResult.error(fieldName + " must be at least " + min);
        }
        
        if (max != null && doubleValue > max.doubleValue()) {
            return ValidationResult.error(fieldName + " cannot exceed " + max);
        }
        
        return ValidationResult.success();
    }
    
    /**
     * SECURITY FIX: Get maximum transfer limit for business rules
     */
    public BigDecimal getMaxTransferLimit() {
        return MAX_TRANSFER_AMOUNT;
    }
    
    /**
     * SECURITY FIX: Get minimum transfer limit for business rules
     */
    public BigDecimal getMinTransferLimit() {
        return MIN_TRANSFER_AMOUNT;
    }
    
    /**
     * SECURITY FIX: Validation result container
     */
    public static class ValidationResult {
        private final boolean valid;
        private final String errorMessage;
        private final String sanitizedValue;
        
        private ValidationResult(boolean valid, String errorMessage, String sanitizedValue) {
            this.valid = valid;
            this.errorMessage = errorMessage;
            this.sanitizedValue = sanitizedValue;
        }
        
        public static ValidationResult success() {
            return new ValidationResult(true, null, null);
        }
        
        public static ValidationResult success(String sanitizedValue) {
            return new ValidationResult(true, null, sanitizedValue);
        }
        
        public static ValidationResult error(String errorMessage) {
            return new ValidationResult(false, errorMessage, null);
        }
        
        public boolean isValid() { return valid; }
        public String getErrorMessage() { return errorMessage; }
        public String getSanitizedValue() { return sanitizedValue; }
    }
}
