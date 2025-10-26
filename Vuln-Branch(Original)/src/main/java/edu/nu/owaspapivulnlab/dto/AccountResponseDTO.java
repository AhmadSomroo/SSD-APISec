package edu.nu.owaspapivulnlab.dto;

/**
 * SECURITY FIX: Account response DTO for safe account data exposure
 * FIXED: API3 Excessive Data Exposure - Controls what account data is exposed
 */
public class AccountResponseDTO {
    private Long id;
    private Double balance;
    private Long ownerUserId;
    
    // SECURITY NOTE: Only essential account information is exposed
    // Internal database fields and sensitive metadata are excluded
    
    public Long getId() {
        return id;
    }
    
    public void setId(Long id) {
        this.id = id;
    }
    
    public Double getBalance() {
        return balance;
    }
    
    public void setBalance(Double balance) {
        this.balance = balance;
    }
    
    public Long getOwnerUserId() {
        return ownerUserId;
    }
    
    public void setOwnerUserId(Long ownerUserId) {
        this.ownerUserId = ownerUserId;
    }
}