package edu.nu.owaspapivulnlab.dto;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotNull;

/**
 * SECURITY FIX: Account transfer request DTO with validation
 * FIXED: API9 Improper Assets Management - Validates transfer amounts
 */
public class AccountTransferRequestDTO {
    @NotNull(message = "Transfer amount is required")
    @DecimalMin(value = "0.01", message = "Transfer amount must be positive")
    private Double amount;
    
    // SECURITY NOTE: Only amount is accepted from client
    // Account ID comes from path parameter and is validated for ownership
    
    public Double getAmount() {
        return amount;
    }
    
    public void setAmount(Double amount) {
        this.amount = amount;
    }
}