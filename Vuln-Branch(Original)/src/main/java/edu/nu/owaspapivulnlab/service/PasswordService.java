package edu.nu.owaspapivulnlab.service;

/**
 * Service interface for secure password operations using BCrypt hashing.
 * Provides methods for password hashing, validation, and strength checking.
 */
public interface PasswordService {
    
    /**
     * Hashes a plaintext password using BCrypt with a secure cost factor.
     * 
     * @param plaintext the plaintext password to hash
     * @return the BCrypt hash of the password
     * @throws IllegalArgumentException if password doesn't meet strength requirements
     */
    String hashPassword(String plaintext);
    
    /**
     * Validates a plaintext password against a BCrypt hash.
     * 
     * @param plaintext the plaintext password to validate
     * @param hash the BCrypt hash to validate against
     * @return true if the password matches the hash, false otherwise
     */
    boolean validatePassword(String plaintext, String hash);
    
    /**
     * Checks if a password meets the minimum strength requirements.
     * 
     * @param password the password to validate
     * @return true if the password meets requirements, false otherwise
     */
    boolean isPasswordStrong(String password);
    
    /**
     * Determines if a hash needs to be rehashed (e.g., cost factor too low).
     * 
     * @param hash the BCrypt hash to check
     * @return true if the hash should be regenerated, false otherwise
     */
    boolean requiresRehashing(String hash);
}