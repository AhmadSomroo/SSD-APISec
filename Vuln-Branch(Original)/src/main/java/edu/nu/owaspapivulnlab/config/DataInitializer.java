package edu.nu.owaspapivulnlab.config;

import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.PasswordService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

/**
 * SECURITY FIX: Data initializer with proper password hashing
 * Ensures all seeded users have BCrypt hashed passwords from the start
 */
@Component
public class DataInitializer implements CommandLineRunner {

    private final AppUserRepository userRepository;
    private final AccountRepository accountRepository;
    private final PasswordService passwordService;

    public DataInitializer(AppUserRepository userRepository, 
                          AccountRepository accountRepository,
                          PasswordService passwordService) {
        this.userRepository = userRepository;
        this.accountRepository = accountRepository;
        this.passwordService = passwordService;
    }

    @Override
    public void run(String... args) throws Exception {
        // Only initialize if database is empty
        if (userRepository.count() == 0) {
            initializeUsers();
            initializeAccounts();
        } else {
            // SECURITY FIX: Migrate existing plaintext passwords to BCrypt
            migrateExistingPasswords();
        }
    }

    private void initializeUsers() {
        // Create admin user with hashed password
        AppUser admin = new AppUser();
        admin.setUsername("admin");
        admin.setPassword(passwordService.hashPassword("admin123"));
        admin.setRole("ADMIN");
        admin.setAdmin(true);
        userRepository.save(admin);

        // Create regular users with hashed passwords
        AppUser alice = new AppUser();
        alice.setUsername("alice");
        alice.setPassword(passwordService.hashPassword("password123"));
        alice.setRole("USER");
        alice.setAdmin(false);
        userRepository.save(alice);

        AppUser bob = new AppUser();
        bob.setUsername("bob");
        bob.setPassword(passwordService.hashPassword("password123"));
        bob.setRole("USER");
        bob.setAdmin(false);
        userRepository.save(bob);

        AppUser charlie = new AppUser();
        charlie.setUsername("charlie");
        charlie.setPassword(passwordService.hashPassword("password123"));
        charlie.setRole("USER");
        charlie.setAdmin(false);
        userRepository.save(charlie);
    }

    private void initializeAccounts() {
        // Create accounts for users
        AppUser alice = userRepository.findByUsername("alice").orElse(null);
        AppUser bob = userRepository.findByUsername("bob").orElse(null);
        AppUser charlie = userRepository.findByUsername("charlie").orElse(null);

        if (alice != null) {
            Account aliceAccount = new Account();
            aliceAccount.setOwnerUserId(alice.getId());
            aliceAccount.setBalance(1000.0);
            accountRepository.save(aliceAccount);
        }

        if (bob != null) {
            Account bobAccount = new Account();
            bobAccount.setOwnerUserId(bob.getId());
            bobAccount.setBalance(1500.0);
            accountRepository.save(bobAccount);
        }

        if (charlie != null) {
            Account charlieAccount = new Account();
            charlieAccount.setOwnerUserId(charlie.getId());
            charlieAccount.setBalance(2000.0);
            accountRepository.save(charlieAccount);
        }
    }

    private void migrateExistingPasswords() {
        // SECURITY FIX: Migrate any existing plaintext passwords to BCrypt
        userRepository.findAll().forEach(user -> {
            String password = user.getPassword();
            if (password != null && !password.startsWith("$2a$")) {
                // Password is not BCrypt hashed, migrate it
                String hashedPassword = passwordService.hashPassword(password);
                user.setPassword(hashedPassword);
                userRepository.save(user);
            }
        });
    }
}