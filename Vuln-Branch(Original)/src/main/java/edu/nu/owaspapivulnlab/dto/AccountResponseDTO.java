package edu.nu.owaspapivulnlab.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * SECURITY FIX: Response DTO for Account data with controlled exposure
 * FIXED: API3 Excessive Data Exposure - Controls what account data is exposed
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccountResponseDTO {
    private Long id;
    private String iban;
    private Double balance;
    
    // SECURITY NOTE: ownerUserId excluded from response
    // - Prevents information leakage about account ownership
    // - Client doesn't need this internal relationship data
}