package edu.nu.owaspapivulnlab.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.Optional;

/**
 * SECURITY FIX: Resource ownership validation service
 * FIXED: API1 BOLA (Broken Object Level Authorization)
 * 
 * This service ensures that users can only access resources they own,
 * preventing horizontal privilege escalation attacks.
 * 
 * Key Features:
 * - Maps JWT subject to user ID for ownership validation
 * - Validates account ownership before allowing access
 * - Supports admin override for administrative operations
 * - Prevents users from accessing other users' resources
 */
@Service
public class ResourceOwnershipValidator {
    
    private final AppUserRepository userRepository;
    private final AccountRepository accountRepository;
    
    public ResourceOwnershipValidator(AppUserRepository userRepository, AccountRepository accountRepository) {
        this.userRepository = userRepository;
        this.accountRepository = accountRepository;
    }
    
    /**
     * SECURITY FIX: Get the current authenticated user ID from JWT subject
     * Maps the JWT subject (username) to the actual user ID for ownership validation
     */
    public Long getCurrentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getName() == null) {
            return null;
        }
        
        Optional<AppUser> user = userRepository.findByUsername(auth.getName());
        return user.map(AppUser::getId).orElse(null);
    }
    
    /**
     * SECURITY FIX: Check if the current user owns the specified account
     * Prevents API1 BOLA attacks by validating account ownership
     */
    public boolean isAccountOwner(Long accountId) {
        Long currentUserId = getCurrentUserId();
        if (currentUserId == null) {
            return false;
        }
        
        Optional<Account> account = accountRepository.findById(accountId);
        return account.map(acc -> currentUserId.equals(acc.getOwnerUserId())).orElse(false);
    }
    
    /**
     * SECURITY FIX: Check if the current user is accessing their own user resource
     * Prevents horizontal privilege escalation in user operations
     */
    public boolean isUserResourceOwner(Long userId) {
        Long currentUserId = getCurrentUserId();
        return currentUserId != null && currentUserId.equals(userId);
    }
    
    /**
     * SECURITY FIX: Check if the current user has admin role
     * Validates admin privileges from JWT claims for role-based access control
     */
    public boolean isAdmin() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) {
            return false;
        }
        
        return auth.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"));
    }
    
    /**
     * Check if the current user can access a user resource (either owns it or is admin)
     */
    public boolean canAccessUserResource(Long userId) {
        return isUserResourceOwner(userId) || isAdmin();
    }
    
    /**
     * Check if the current user can access an account resource (either owns it or is admin)
     */
    public boolean canAccessAccountResource(Long accountId) {
        return isAccountOwner(accountId) || isAdmin();
    }
}