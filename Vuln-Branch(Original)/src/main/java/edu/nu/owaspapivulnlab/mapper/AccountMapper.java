package edu.nu.owaspapivulnlab.mapper;

import edu.nu.owaspapivulnlab.dto.AccountResponseDTO;
import edu.nu.owaspapivulnlab.model.Account;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

/**
 * SECURITY FIX: Account mapper for safe entity-DTO conversion
 * Ensures only appropriate account data is exposed
 */
@Component
public class AccountMapper {

    /**
     * Convert Account entity to safe response DTO
     * SECURITY: Only exposes essential account information
     */
    public AccountResponseDTO toResponseDTO(Account account) {
        if (account == null) {
            return null;
        }
        
        AccountResponseDTO dto = new AccountResponseDTO();
        dto.setId(account.getId());
        dto.setBalance(account.getBalance());
        dto.setOwnerUserId(account.getOwnerUserId());
        return dto;
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