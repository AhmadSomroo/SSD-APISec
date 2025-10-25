package edu.nu.owaspapivulnlab.mapper;

import edu.nu.owaspapivulnlab.dto.UserCreateRequestDTO;
import edu.nu.owaspapivulnlab.dto.UserResponseDTO;
import edu.nu.owaspapivulnlab.model.AppUser;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

/**
 * SECURITY FIX: Mapper for safe User entity-DTO conversion
 * FIXED: API3 Excessive Data Exposure - Controls what data is exposed to clients
 */
@Component
public class UserMapper {
    
    /**
     * Convert AppUser entity to safe response DTO
     * Excludes sensitive fields: password, role, isAdmin
     */
    public UserResponseDTO toResponseDTO(AppUser user) {
        if (user == null) {
            return null;
        }
        
        return UserResponseDTO.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .build();
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
     * Convert create request DTO to AppUser entity
     * Server controls role and isAdmin - prevents mass assignment
     */
    public AppUser toEntity(UserCreateRequestDTO dto) {
        if (dto == null) {
            return null;
        }
        
        return AppUser.builder()
                .username(dto.getUsername())
                .password(dto.getPassword()) // Will be hashed by service layer
                .email(dto.getEmail())
                .role("USER") // SECURITY: Server-controlled, always USER for new accounts
                .isAdmin(false) // SECURITY: Server-controlled, always false for new accounts
                .build();
    }
}