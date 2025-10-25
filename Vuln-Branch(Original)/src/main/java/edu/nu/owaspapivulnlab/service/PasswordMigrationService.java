package edu.nu.owaspapivulnlab.service;

import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Service responsible for migrating existing plaintext passwords to BCrypt hashes.
 * Runs at application startup to ensure all passwords are properly secured.
 */
@Service
@Order(1000) // Run after data seeding
public class PasswordMigrationService implements CommandLineRunner {
    
    private final AppUserRepository userRepository;
    private final PasswordService passwordService;
    
    public PasswordMigrationService(AppUserRepository userRepository, PasswordService passwordService) {
        this.userRepository = userRepository;
        this.passwordService = passwordService;
    }
    
    @Override
    @Transactional
    public void run(String... args) throws Exception {
        migratePasswords();
    }
    
    /**
     * Migrates all plaintext passwords to BCrypt hashes.
     * Only processes passwords that are not already hashed.
     */
    public void migratePasswords() {
        List<AppUser> users = userRepository.findAll();
        int migratedCount = 0;
        
        for (AppUser user : users) {
            if (needsMigration(user.getPassword())) {
                try {
                    String originalPassword = user.getPassword();
                    String hashedPassword = passwordService.hashPassword(originalPassword);
                    user.setPassword(hashedPassword);
                    userRepository.save(user);
                    migratedCount++;
                    
                    // Log migration (in production, use proper logging)
                    System.out.println("Migrated password for user: " + user.getUsername());
                } catch (Exception e) {
                    // Log error but continue with other users
                    System.err.println("Failed to migrate password for user " + user.getUsername() + ": " + e.getMessage());
                }
            }
        }
        
        if (migratedCount > 0) {
            System.out.println("Password migration completed. Migrated " + migratedCount + " passwords.");
        } else {
            System.out.println("No password migration needed. All passwords are already hashed.");
        }
    }
    
    /**
     * Determines if a password needs migration from plaintext to BCrypt.
     * 
     * @param password the password to check
     * @return true if the password needs migration, false if already hashed
     */
    private boolean needsMigration(String password) {
        if (password == null || password.isEmpty()) {
            return false;
        }
        
        // BCrypt hashes start with $2a$, $2b$, $2x$, or $2y$
        return !password.startsWith("$2");
    }
    
    /**
     * Manually trigger password migration (useful for testing or manual operations).
     * 
     * @return the number of passwords migrated
     */
    @Transactional
    public int triggerMigration() {
        List<AppUser> users = userRepository.findAll();
        int migratedCount = 0;
        
        for (AppUser user : users) {
            if (needsMigration(user.getPassword())) {
                try {
                    String hashedPassword = passwordService.hashPassword(user.getPassword());
                    user.setPassword(hashedPassword);
                    userRepository.save(user);
                    migratedCount++;
                } catch (Exception e) {
                    // Log error but continue
                    System.err.println("Migration failed for user " + user.getUsername() + ": " + e.getMessage());
                }
            }
        }
        
        return migratedCount;
    }
}