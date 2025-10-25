package edu.nu.owaspapivulnlab.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

@Configuration
public class DataSeeder {
    @Bean
    CommandLineRunner seed(AppUserRepository users, AccountRepository accounts) {
        return args -> {
            if (users.count() == 0) {
                AppUser u1 = new AppUser();
                u1.setUsername("alice");
                u1.setPassword("alice123");
                u1.setEmail("alice@cydea.tech");
                u1.setRole("USER");
                u1.setAdmin(false);
                u1 = users.save(u1);
                
                AppUser u2 = new AppUser();
                u2.setUsername("bob");
                u2.setPassword("bob123");
                u2.setEmail("bob@cydea.tech");
                u2.setRole("ADMIN");
                u2.setAdmin(true);
                u2 = users.save(u2);
                
                Account acc1 = new Account();
                acc1.setOwnerUserId(u1.getId());
                acc1.setIban("PK00-ALICE");
                acc1.setBalance(1000.0);
                accounts.save(acc1);
                
                Account acc2 = new Account();
                acc2.setOwnerUserId(u2.getId());
                acc2.setIban("PK00-BOB");
                acc2.setBalance(5000.0);
                accounts.save(acc2);
            }
        };
    }
}
