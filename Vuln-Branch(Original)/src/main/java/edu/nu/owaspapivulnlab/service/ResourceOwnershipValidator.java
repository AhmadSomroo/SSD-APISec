package edu.nu.owaspapivulnlab.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.Optional;

@Service
public class ResourceOwnershipValidator {
    
    private final AppUserRepository userRepository;
    private final AccountRepository accountRepository;
    
    public ResourceOwnershipValidator(AppUserRepository userRepository, AccountRepository accountRepository) {
        this.userRepository = userRepository;
        this.accountRepository = accountRepository;
    }
    
    /**
     * Get the current authenticated user ID from JWT subject
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
     * Check if the current user owns the specified account
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
     * Check if the current user is accessing their own user resource
     */
    public boolean isUserResourceOwner(Long userId) {
        Long currentUserId = getCurrentUserId();
        return currentUserId != null && currentUserId.equals(userId);
    }
    
    /**
     * Check if the current user has admin role
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