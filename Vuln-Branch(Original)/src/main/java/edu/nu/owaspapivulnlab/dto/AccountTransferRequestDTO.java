package edu.nu.owaspapivulnlab.dto;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * SECURITY FIX: Request DTO for account transfers with validation
 * FIXED: API9 Improper Assets Management - Validates transfer amounts
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccountTransferRequestDTO {
    @NotNull(message = "Transfer amount is required")
    @DecimalMin(value = "0.01", message = "Transfer amount must be positive")
    private Double amount;
    
    // SECURITY NOTE: Account ID comes from path parameter, not request body
    // This prevents users from manipulating which account the transfer comes from
}