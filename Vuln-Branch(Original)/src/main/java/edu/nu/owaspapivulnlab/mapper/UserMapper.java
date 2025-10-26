package edu.nu.owaspapivulnlab.mapper;

import edu.nu.owaspapivulnlab.dto.UserCreateRequestDTO;
import edu.nu.owaspapivulnlab.dto.UserResponseDTO;
import edu.nu.owaspapivulnlab.model.AppUser;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

/**
 * SECURITY FIX: User mapper for safe entity-DTO conversion
 * Ensures sensitive fields are never exposed in responses
 */
@Component
public class UserMapper {

    /**
     * Convert AppUser entity to safe response DTO
     * SECURITY: Excludes password, role, and isAdmin fields
     */
    public UserResponseDTO toResponseDTO(AppUser user) {
        if (user == null) {
            return null;
        }
        
        UserResponseDTO dto = new UserResponseDTO();
        dto.setId(user.getId());
        dto.setUsername(user.getUsername());
        // SECURITY: Sensitive fields intentionally excluded
        return dto;
    }

    /**
     * Convert list of AppUser entities to response DTOs
     */
    public List<UserResponseDTO> toResponseDTOs(List<AppUser> users) {
        return users.stream()
                .map(this::toResponseDTO)
                .collect(Collectors.toList());
    }

    /**
     * Convert request DTO to AppUser entity for creation
     * SECURITY: Server controls role and isAdmin assignment
     */
    public AppUser toEntity(UserCreateRequestDTO dto) {
        if (dto == null) {
            return null;
        }
        
        AppUser user = new AppUser();
        user.setUsername(dto.getUsername());
        user.setPassword(dto.getPassword()); // Will be hashed by service
        // SECURITY FIX: Server-side assignment prevents mass assignment
        user.setRole("USER"); // Always USER for new accounts
        user.setAdmin(false); // Always false for new accounts
        return user;
    }
}