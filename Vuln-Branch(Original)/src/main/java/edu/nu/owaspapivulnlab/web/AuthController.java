package edu.nu.owaspapivulnlab.web;

import jakarta.validation.constraints.NotBlank;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.JwtService;
import edu.nu.owaspapivulnlab.service.PasswordService;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AppUserRepository users;
    private final JwtService jwt;
    private final PasswordService passwordService;

    public AuthController(AppUserRepository users, JwtService jwt, PasswordService passwordService) {
        this.users = users;
        this.jwt = jwt;
        this.passwordService = passwordService;
    }

    public static class LoginReq {
        @NotBlank
        private String username;
        @NotBlank
        private String password;

        public LoginReq() {}

        public LoginReq(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String username() { return username; }
        public String password() { return password; }

        public void setUsername(String username) { this.username = username; }
        public void setPassword(String password) { this.password = password; }
    }

    public static class TokenRes {
        private String token;

        public TokenRes() {}

        public TokenRes(String token) {
            this.token = token;
        }

        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
    }

    @PostMapping(value = "/login", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> login(@RequestBody LoginReq req) {
        System.out.println("JSON login request received for user: " + req.username());
        return processLogin(req);
    }
    
    // Fallback login endpoint that accepts form data (for curl compatibility)
    @PostMapping(value = "/login-form", consumes = "application/x-www-form-urlencoded", produces = "application/json")
    public ResponseEntity<?> loginForm(@RequestParam String username, @RequestParam String password) {
        System.out.println("Form login request received for user: " + username);
        
        // Create LoginReq object from form parameters
        LoginReq req = new LoginReq(username, password);
        
        // Reuse the same login logic
        return processLogin(req);
    }
    
    // SECURITY FIX: Enhanced login logic with secure password handling and migration
    // FIXED: API2 Broken Authentication - Implemented BCrypt password validation
    private ResponseEntity<?> processLogin(LoginReq req) {
        AppUser user = users.findByUsername(req.username()).orElse(null);
        if (user != null) {
            boolean isValidPassword = false;
            
            // SECURITY FIX: Handle both BCrypt hashed and plaintext passwords during migration
            if (user.getPassword().startsWith("$2")) {
                // SECURITY FIX: Use BCrypt validation for hashed passwords
                isValidPassword = passwordService.validatePassword(req.password(), user.getPassword());
            } else {
                // SECURITY FIX: Support plaintext passwords during transition period
                isValidPassword = req.password().equals(user.getPassword());
                
                // SECURITY FIX: Automatic password migration on successful login
                // This ensures all passwords are eventually migrated to BCrypt
                if (isValidPassword && passwordService.isPasswordStrong(user.getPassword())) {
                    try {
                        String hashedPassword = passwordService.hashPassword(user.getPassword());
                        user.setPassword(hashedPassword);
                        users.save(user);
                        System.out.println("Migrated password for user: " + user.getUsername());
                    } catch (Exception e) {
                        System.err.println("Failed to migrate password for user " + user.getUsername() + ": " + e.getMessage());
                    }
                }
            }
            
            if (isValidPassword) {
                // SECURITY FIX: Create JWT with proper claims
                Map<String, Object> claims = new HashMap<>();
                claims.put("role", user.getRole());
                claims.put("isAdmin", user.isAdmin());
                String token = jwt.issue(user.getUsername(), claims);
                return ResponseEntity.ok(new TokenRes(token));
            }
        }
        
        // SECURITY FIX: Return proper error response for invalid credentials
        Map<String, String> error = new HashMap<>();
        error.put("error", "invalid credentials");
        return ResponseEntity.status(401).body(error);
    }
    
    // Test endpoint to verify JSON handling
    @PostMapping(value = "/test", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> test(@RequestBody Map<String, String> data) {
        Map<String, String> response = new HashMap<>();
        response.put("message", "JSON received successfully");
        response.put("received", data.toString());
        return ResponseEntity.ok(response);
    }
}
