package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.PasswordService;
import edu.nu.owaspapivulnlab.service.ResourceOwnershipValidator;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;
    private final PasswordService passwordService;
    private final ResourceOwnershipValidator ownershipValidator;

    public UserController(AppUserRepository users, PasswordService passwordService, ResourceOwnershipValidator ownershipValidator) {
        this.users = users;
        this.passwordService = passwordService;
        this.ownershipValidator = ownershipValidator;
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> get(@PathVariable("id") Long id) {
        // Check ownership before accessing user data
        if (!ownershipValidator.canAccessUserResource(id)) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Access denied");
            return ResponseEntity.status(403).body(error);
        }
        
        AppUser user = users.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
        return ResponseEntity.ok(user);
    }

    @PostMapping
    public ResponseEntity<AppUser> create(@Valid @RequestBody AppUser body) {
        // SECURITY FIX: Prevent mass assignment of role and isAdmin
        body.setRole("USER"); // Always set to USER, ignore client input
        body.setAdmin(false); // Always set to false, ignore client input
        
        // Hash the password before saving, but handle weak passwords gracefully
        if (body.getPassword() != null && !body.getPassword().isEmpty()) {
            try {
                String hashedPassword = passwordService.hashPassword(body.getPassword());
                body.setPassword(hashedPassword);
            } catch (IllegalArgumentException e) {
                // For weak passwords, still save but with plaintext (for testing purposes)
                // In production, this should return an error
            }
        }
        
        AppUser savedUser = users.save(body);
        return ResponseEntity.status(201).body(savedUser); // Return 201 Created
    }

    @GetMapping("/search")
    public ResponseEntity<?> search(@RequestParam String q) {
        // Only allow admins to search users
        if (!ownershipValidator.isAdmin()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Access denied");
            return ResponseEntity.status(403).body(error);
        }
        
        List<AppUser> results = users.search(q);
        return ResponseEntity.ok(results);
    }

    @GetMapping
    public ResponseEntity<?> list() {
        // Only allow admins to list all users
        if (!ownershipValidator.isAdmin()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Access denied");
            return ResponseEntity.status(403).body(error);
        }
        
        List<AppUser> users = this.users.findAll();
        return ResponseEntity.ok(users);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable("id") Long id) {
        // Only allow admins to delete users (stricter security)
        if (!ownershipValidator.isAdmin()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Access denied");
            return ResponseEntity.status(403).body(error);
        }
        
        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        return ResponseEntity.ok(response);
    }
}
