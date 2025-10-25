package edu.nu.owaspapivulnlab.mapper;

import edu.nu.owaspapivulnlab.dto.AccountResponseDTO;
import edu.nu.owaspapivulnlab.model.Account;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

/**
 * SECURITY FIX: Mapper for safe Account entity-DTO conversion
 * FIXED: API3 Excessive Data Exposure - Controls what account data is exposed
 */
@Component
public class AccountMapper {
    
    /**
     * Convert Account entity to safe response DTO
     * Excludes ownerUserId to prevent information leakage
     */
    public AccountResponseDTO toResponseDTO(Account account) {
        if (account == null) {
            return null;
        }
        
        return AccountResponseDTO.builder()
                .id(account.getId())
                .iban(account.getIban())
                .balance(account.getBalance())
                .build();
    }
    
    /**
     * Convert list of Account entities to response DTOs
     */
    public List<AccountResponseDTO> toResponseDTOs(List<Account> accounts) {
        return accounts.stream()
                .map(this::toResponseDTO)
                .collect(Collectors.toList());
    }
}