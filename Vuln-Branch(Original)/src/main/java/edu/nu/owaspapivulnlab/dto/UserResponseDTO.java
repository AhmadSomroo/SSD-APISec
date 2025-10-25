package edu.nu.owaspapivulnlab.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * SECURITY FIX: Response DTO for User data that excludes sensitive fields
 * FIXED: API3 Excessive Data Exposure - Prevents exposure of password, role, and isAdmin
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserResponseDTO {
    private Long id;
    private String username;
    private String email;
    
    // SECURITY NOTE: Sensitive fields excluded:
    // - password (never expose, even if hashed)
    // - role (internal authorization data)
    // - isAdmin (internal authorization data)
}