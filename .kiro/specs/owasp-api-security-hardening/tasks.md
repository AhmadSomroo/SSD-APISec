# Implementation Plan

- [x] 1. Set up security foundation and password hashing





  - BCrypt implementation
  - Add BCrypt dependency and configuration
  - Implement password strength validation
  - Give before and after implementation with brief explanation
  - _Requirements: 1.1, 1.4_

- [x] 1.1 Implement BCrypt password service


  - Create PasswordService interface with hash and validate methods
  - Implement BCryptPasswordService with cost factor 12
  - Add password strength validation (minimum 8 characters)
  - _Requirements: 1.1, 1.4_

- [x] 1.2 Create password migration service


  - Implement service to migrate existing plaintext passwords to BCrypt
  - Add startup migration logic for seeded user data
  - Ensure migration runs only once and handles edge cases
  - _Requirements: 1.3_

- [x] 1.3 Update authentication flow to use BCrypt


  - Modify AuthController login method to use BCrypt validation
  - Remove plaintext password comparison logic
  - Update user creation to hash passwords before saving
  - _Requirements: 1.1, 1.2_

- [ ]* 1.4 Write unit tests for password security
  - Test BCrypt hashing and validation functionality
  - Test password strength validation rules
  - Test migration service behavior
  - _Requirements: 1.1, 1.4_

- [ ] 2. Harden JWT token security
  - Enhance JWT service with stronger security controls
  - Implement environment-based secret key management
  - Add issuer and audience claim validation
  - _Requirements: 7.1, 7.3, 7.4_

- [ ] 2.1 Enhance JWT service configuration
  - Move JWT secret to environment variable with strong default
  - Reduce token TTL to 15 minutes maximum
  - Add issuer and audience claims to token generation
  - _Requirements: 7.1, 7.2, 7.3_

- [ ] 2.2 Strengthen JWT validation in security filter
  - Update JwtFilter to validate issuer and audience claims
  - Implement strict signature and expiry validation
  - Add proper error handling for invalid tokens
  - _Requirements: 7.4, 7.5_

- [ ]* 2.3 Write unit tests for JWT security
  - Test token generation with all required claims
  - Test token validation with various invalid scenarios
  - Test environment variable configuration
  - _Requirements: 7.1, 7.3, 7.4_

- [x] 3. Implement strict access control and authorization





  - Remove permitAll from GET /api/** endpoints
  - Enforce authentication for all protected endpoints
  - Implement role-based access control for admin functions
  - _Requirements: 2.1, 2.2, 2.3, 2.4_

- [x] 3.1 Update SecurityFilterChain configuration


  - Remove permitAll from /api/** GET endpoints
  - Require authentication for all endpoints except auth endpoints
  - Ensure proper role-based access for admin endpoints
  - _Requirements: 2.1, 2.2, 2.3_

- [x] 3.2 Implement resource ownership validation service


  - Create ResourceOwnershipValidator to check user ownership
  - Add utility methods to map JWT subject to user ID
  - Implement ownership validation for accounts and user resources
  - _Requirements: 3.1, 3.2, 3.3, 3.4_

- [x] 3.3 Update controllers with ownership validation


  - Add ownership checks to AccountController methods
  - Add ownership checks to UserController methods
  - Ensure proper HTTP 403 responses for unauthorized access
  - _Requirements: 3.1, 3.2, 3.5_

- [ ]* 3.4 Write integration tests for access control
  - Test authentication requirements for protected endpoints
  - Test role-based access control for admin functions
  - Test resource ownership validation
  - _Requirements: 2.2, 2.4, 3.2_

- [ ] 4. Implement DTO system for data exposure control
  - Create request and response DTOs for all entities
  - Implement DTO mapping utilities
  - Update controllers to use DTOs instead of entities
  - _Requirements: 4.1, 4.2, 4.3, 4.4_

- [ ] 4.1 Create user DTOs and mappers
  - Create UserResponseDTO excluding sensitive fields
  - Create UserCreateRequestDTO for user creation
  - Implement UserMapper for entity-DTO conversion
  - _Requirements: 4.1, 4.2, 4.3_

- [ ] 4.2 Create account DTOs and mappers
  - Create AccountResponseDTO for safe account data exposure
  - Create AccountTransferRequestDTO for transfer operations
  - Implement AccountMapper for entity-DTO conversion
  - _Requirements: 4.3, 4.4_

- [ ] 4.3 Update controllers to use DTOs
  - Modify UserController to use DTOs for all operations
  - Modify AccountController to use DTOs for responses
  - Ensure no entity objects are directly returned to clients
  - _Requirements: 4.3, 4.4, 4.5_

- [ ]* 4.4 Write unit tests for DTO system
  - Test DTO mapping functionality
  - Test that sensitive fields are excluded from responses
  - Test request DTO validation
  - _Requirements: 4.1, 4.2, 4.3_

- [ ] 5. Prevent mass assignment vulnerabilities
  - Implement request DTOs that exclude sensitive fields
  - Add server-side validation for user creation
  - Ensure role and isAdmin cannot be set by clients
  - _Requirements: 6.1, 6.2, 6.3, 6.4_

- [ ] 5.1 Create secure user creation flow
  - Update UserController to use UserCreateRequestDTO
  - Implement server-side role assignment (default USER)
  - Ensure isAdmin is always set to false for new users
  - _Requirements: 6.1, 6.2, 6.4_

- [ ] 5.2 Add comprehensive input validation
  - Add Bean Validation annotations to all request DTOs
  - Implement custom validators for business rules
  - Add proper validation error handling and responses
  - _Requirements: 6.3, 6.5_

- [ ]* 5.3 Write integration tests for mass assignment prevention
  - Test that role escalation is prevented during user creation
  - Test that sensitive fields are ignored in requests
  - Test validation error responses
  - _Requirements: 6.1, 6.2, 6.3_

- [ ] 6. Implement rate limiting for abuse prevention
  - Add Bucket4j dependency for rate limiting
  - Implement rate limiting for critical endpoints
  - Configure different limits for different endpoint types
  - _Requirements: 5.1, 5.2, 5.3, 5.4_

- [ ] 6.1 Set up rate limiting infrastructure
  - Add Bucket4j dependency to pom.xml
  - Create RateLimitingService with configurable limits
  - Implement rate limiting filter for HTTP requests
  - _Requirements: 5.1, 5.4_

- [ ] 6.2 Configure endpoint-specific rate limits
  - Implement 5 requests/minute limit for login endpoints
  - Implement 10 requests/minute limit for transfer operations
  - Add different limits for authenticated vs anonymous users
  - _Requirements: 5.1, 5.2, 5.5_

- [ ] 6.3 Add rate limit exceeded handling
  - Return HTTP 429 when rate limits are exceeded
  - Include appropriate headers for rate limit status
  - Log rate limit violations for monitoring
  - _Requirements: 5.3_

- [ ]* 6.4 Write integration tests for rate limiting
  - Test rate limit enforcement for different endpoints
  - Test rate limit exceeded responses
  - Test different limits for different user types
  - _Requirements: 5.1, 5.2, 5.3_

- [ ] 7. Enhance input validation and security
  - Implement comprehensive input validation rules
  - Add validation for transfer amounts and numeric inputs
  - Implement input sanitization to prevent injection
  - _Requirements: 9.1, 9.2, 9.3, 9.4_

- [ ] 7.1 Implement transfer amount validation
  - Add validation to reject negative transfer amounts
  - Implement maximum transfer limits per transaction
  - Add balance validation before processing transfers
  - _Requirements: 9.1, 9.2_

- [ ] 7.2 Add comprehensive numeric input validation
  - Validate all numeric inputs for reasonable ranges
  - Reject excessively large or invalid numeric values
  - Add proper error messages for validation failures
  - _Requirements: 9.3, 9.5_

- [ ] 7.3 Implement string input sanitization
  - Add input sanitization for search queries
  - Implement validation for string length and format
  - Add protection against injection attacks in user inputs
  - _Requirements: 9.4_

- [ ]* 7.4 Write unit tests for input validation
  - Test transfer amount validation rules
  - Test numeric input boundary conditions
  - Test string sanitization functionality
  - _Requirements: 9.1, 9.2, 9.3_

- [ ] 8. Implement secure error handling and logging
  - Create custom exception handlers for security errors
  - Implement secure logging for security events
  - Ensure no sensitive information leaks in error responses
  - _Requirements: 8.1, 8.2, 8.3, 8.4_

- [ ] 8.1 Create global security exception handler
  - Implement GlobalSecurityExceptionHandler for centralized error handling
  - Create generic error responses that don't leak sensitive information
  - Add proper HTTP status codes for different error types
  - _Requirements: 8.1, 8.3_

- [ ] 8.2 Implement security audit logging
  - Create SecurityAuditService for logging security events
  - Log authentication attempts, authorization failures, and security violations
  - Implement structured logging with correlation IDs
  - _Requirements: 8.2, 8.5_

- [ ] 8.3 Update application configuration for secure error handling
  - Remove stack trace exposure from application.properties
  - Configure production-safe error message levels
  - Ensure detailed errors are only logged server-side
  - _Requirements: 8.1, 8.4_

- [ ]* 8.4 Write unit tests for error handling
  - Test that generic error messages are returned to clients
  - Test that detailed information is logged server-side
  - Test security event logging functionality
  - _Requirements: 8.1, 8.2, 8.3_

- [ ] 9. Update and enhance security tests
  - Fix existing failing security tests
  - Add comprehensive security validation tests
  - Implement vulnerability verification tests
  - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_

- [ ] 9.1 Fix existing security expectation tests
  - Update AdditionalSecurityExpectationsTests to pass with hardened security
  - Ensure all authentication and authorization tests pass
  - Verify mass assignment prevention tests work correctly
  - _Requirements: 10.1, 10.2, 10.4_

- [ ] 9.2 Add comprehensive authentication tests
  - Test BCrypt password validation
  - Test JWT token security with issuer/audience validation
  - Test authentication bypass prevention
  - _Requirements: 10.1_

- [ ] 9.3 Add authorization and access control tests
  - Test role-based access control enforcement
  - Test resource ownership validation
  - Test privilege escalation prevention
  - _Requirements: 10.2_

- [ ] 9.4 Add data protection and validation tests
  - Test DTO data filtering and exposure control
  - Test mass assignment prevention
  - Test input validation and sanitization
  - _Requirements: 10.3, 10.4_

- [ ] 9.5 Add rate limiting and security monitoring tests
  - Test rate limiting effectiveness and enforcement
  - Test security event logging and audit functionality
  - Test error handling security measures
  - _Requirements: 10.5_

- [ ] 10. Final integration and verification
  - Run complete test suite to verify all vulnerabilities are fixed
  - Perform end-to-end security validation
  - Document security improvements and test results
  - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_

- [ ] 10.1 Execute comprehensive security test suite
  - Run all unit and integration tests
  - Verify all OWASP API Top 10 vulnerabilities are addressed
  - Ensure no regressions in functionality
  - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_

- [ ] 10.2 Perform security validation and documentation
  - Document all security improvements implemented
  - Create security testing report comparing before/after results
  - Verify application maintains full functionality with enhanced security
  - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_