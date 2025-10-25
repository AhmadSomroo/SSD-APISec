package edu.nu.owaspapivulnlab.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * SECURITY FIX: User creation request DTO that prevents mass assignment
 * FIXED: API6 Mass Assignment - Excludes role and isAdmin fields from client input
 */
public class UserCreateRequestDTO {
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;
    
    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    private String password;
    
    private String email; // Optional field for user creation
    
    // SECURITY NOTE: Sensitive fields excluded to prevent mass assignment:
    // - role (server assigns USER role by default)
    // - isAdmin (server assigns false by default)
    
    public String getUsername() {
        return username;
    }
    
    public void setUsername(String username) {
        this.username = username;
    }
    
    public String getPassword() {
        return password;
    }
    
    public void setPassword(String password) {
        this.password = password;
    }
    
    public String getEmail() {
        return email;
    }
    
    public void setEmail(String email) {
        this.email = email;
    }
}