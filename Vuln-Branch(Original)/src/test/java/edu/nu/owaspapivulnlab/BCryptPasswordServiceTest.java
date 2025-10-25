package edu.nu.owaspapivulnlab;

import edu.nu.owaspapivulnlab.service.BCryptPasswordService;
import edu.nu.owaspapivulnlab.service.PasswordService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class BCryptPasswordServiceTest {

    private final PasswordService passwordService = new BCryptPasswordService();

    @Test
    void testPasswordHashing() {
        String plaintext = "alice123";
        String hash = passwordService.hashPassword(plaintext);
        
        // Verify hash is generated
        assertNotNull(hash);
        assertNotEquals(plaintext, hash);
        assertTrue(hash.startsWith("$2a$12$")); // BCrypt format with cost 12
    }

    @Test
    void testPasswordValidation() {
        String plaintext = "alice123";
        String hash = passwordService.hashPassword(plaintext);
        
        // Verify correct password validates
        assertTrue(passwordService.validatePassword(plaintext, hash));
        
        // Verify incorrect password fails
        assertFalse(passwordService.validatePassword("wrongpassword", hash));
    }

    @Test
    void testPasswordStrengthValidation() {
        // Valid password (8+ characters)
        assertTrue(passwordService.isPasswordStrong("alice123"));
        
        // Invalid password (too short)
        assertFalse(passwordService.isPasswordStrong("short"));
        
        // Invalid password (null)
        assertFalse(passwordService.isPasswordStrong(null));
    }

    @Test
    void testPasswordHashingFailsForWeakPassword() {
        // Should throw exception for weak password
        assertThrows(IllegalArgumentException.class, () -> {
            passwordService.hashPassword("weak");
        });
    }

    @Test
    void testRequiresRehashing() {
        String bcryptHash = "$2a$12$abcdefghijklmnopqrstuvwxyz";
        String plaintextHash = "plaintext";
        
        // BCrypt hash with cost 12 should not require rehashing
        assertFalse(passwordService.requiresRehashing(bcryptHash));
        
        // Plaintext should require rehashing
        assertTrue(passwordService.requiresRehashing(plaintextHash));
        
        // Lower cost should require rehashing
        String lowCostHash = "$2a$10$abcdefghijklmnopqrstuvwxyz";
        assertTrue(passwordService.requiresRehashing(lowCostHash));
    }
}