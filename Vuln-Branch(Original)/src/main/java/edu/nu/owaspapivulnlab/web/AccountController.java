package edu.nu.owaspapivulnlab.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.ResourceOwnershipValidator;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;
    private final ResourceOwnershipValidator ownershipValidator;

    public AccountController(AccountRepository accounts, AppUserRepository users, ResourceOwnershipValidator ownershipValidator) {
        this.accounts = accounts;
        this.users = users;
        this.ownershipValidator = ownershipValidator;
    }

    @GetMapping("/{id}/balance")
    public ResponseEntity<?> balance(@PathVariable("id") Long id) {
        // Check ownership before accessing account
        if (!ownershipValidator.canAccessAccountResource(id)) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Access denied");
            return ResponseEntity.status(403).body(error);
        }
        
        Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));
        return ResponseEntity.ok(a.getBalance());
    }

    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(@PathVariable("id") Long id, @RequestParam Double amount) {
        // Check ownership before processing transfer
        if (!ownershipValidator.canAccessAccountResource(id)) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Access denied");
            return ResponseEntity.status(403).body(error);
        }
        
        Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));
        a.setBalance(a.getBalance() - amount);
        accounts.save(a);
        Map<String, Object> response = new HashMap<>();
        response.put("status", "ok");
        response.put("remaining", a.getBalance());
        return ResponseEntity.ok(response);
    }

    // Safe-ish helper to view my accounts (still leaks more than needed)
    @GetMapping("/mine")
    public Object mine(Authentication auth) {
        AppUser me = users.findByUsername(auth != null ? auth.getName() : "anonymous").orElse(null);
        return me == null ? Collections.emptyList() : accounts.findByOwnerUserId(me.getId());
    }
}
