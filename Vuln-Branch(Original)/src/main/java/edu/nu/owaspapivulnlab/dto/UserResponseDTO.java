package edu.nu.owaspapivulnlab.dto;

/**
 * SECURITY FIX: User response DTO that excludes sensitive fields
 * FIXED: API3 Excessive Data Exposure - Prevents exposure of password, role, and isAdmin
 */
public class UserResponseDTO {
    private Long id;
    private String username;
    
    // SECURITY NOTE: Sensitive fields excluded:
    // - password (never expose, even if hashed)
    // - role (internal authorization data)
    // - isAdmin (internal authorization flag)
    
    public Long getId() {
        return id;
    }
    
    public void setId(Long id) {
        this.id = id;
    }
    
    public String getUsername() {
        return username;
    }
    
    public void setUsername(String username) {
        this.username = username;
    }
}