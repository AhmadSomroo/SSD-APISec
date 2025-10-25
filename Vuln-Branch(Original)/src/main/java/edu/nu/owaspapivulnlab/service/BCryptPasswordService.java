package edu.nu.owaspapivulnlab.service;

import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * BCrypt implementation of PasswordService providing secure password hashing.
 * Uses BCrypt with cost factor 12 for strong password protection.
 */
@Service
public class BCryptPasswordService implements PasswordService {
    
    private static final int BCRYPT_COST_FACTOR = 12;
    private static final int MIN_PASSWORD_LENGTH = 8;
    
    private final BCryptPasswordEncoder encoder;
    
    public BCryptPasswordService() {
        this.encoder = new BCryptPasswordEncoder(BCRYPT_COST_FACTOR);
    }
    
    @Override
    public String hashPassword(String plaintext) {
        if (plaintext == null || plaintext.trim().isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        
        if (!isPasswordStrong(plaintext)) {
            throw new IllegalArgumentException("Password does not meet strength requirements");
        }
        
        return encoder.encode(plaintext);
    }
    
    @Override
    public boolean validatePassword(String plaintext, String hash) {
        if (plaintext == null || hash == null) {
            return false;
        }
        
        try {
            return encoder.matches(plaintext, hash);
        } catch (Exception e) {
            // Log the exception in a real application
            return false;
        }
    }
    
    @Override
    public boolean isPasswordStrong(String password) {
        if (password == null) {
            return false;
        }
        
        // Minimum length requirement
        if (password.length() < MIN_PASSWORD_LENGTH) {
            return false;
        }
        
        // Additional strength requirements can be added here
        // For now, we only enforce minimum length as per requirements
        return true;
    }
    
    @Override
    public boolean requiresRehashing(String hash) {
        if (hash == null || !hash.startsWith("$2")) {
            return true; // Not a BCrypt hash or invalid format
        }
        
        try {
            // Extract cost factor from BCrypt hash
            // BCrypt format: $2a$rounds$salt+hash
            String[] parts = hash.split("\\$");
            if (parts.length >= 3) {
                int currentCost = Integer.parseInt(parts[2]);
                return currentCost < BCRYPT_COST_FACTOR;
            }
        } catch (NumberFormatException e) {
            return true; // Invalid format, should rehash
        }
        
        return false;
    }
}