# Design Document

## Overview

This design document outlines the systematic security hardening of the OWASP API Vulnerability Lab application. The current application demonstrates all major OWASP API Security Top 10 vulnerabilities and requires comprehensive security improvements while maintaining existing functionality. The design follows defense-in-depth principles, implementing multiple layers of security controls including authentication hardening, authorization enforcement, data protection, and comprehensive input validation.

## Architecture

### Current Architecture Analysis

The application follows a standard Spring Boot layered architecture:
- **Web Layer**: REST controllers handling HTTP requests
- **Service Layer**: Business logic and JWT token management
- **Repository Layer**: JPA repositories for data access
- **Model Layer**: JPA entities representing domain objects
- **Configuration Layer**: Security and application configuration

### Security Architecture Enhancements

The hardened architecture will implement:

1. **Security Filter Chain**: Enhanced with proper authentication requirements
2. **Password Security Layer**: BCrypt hashing service for credential protection
3. **Authorization Layer**: Role-based access control with resource ownership validation
4. **DTO Layer**: Data transfer objects to control information exposure
5. **Rate Limiting Layer**: Request throttling to prevent abuse
6. **Validation Layer**: Comprehensive input validation and sanitization
7. **Audit Layer**: Security event logging and monitoring

## Components and Interfaces

### 1. Password Security Component

**Purpose**: Replace plaintext password storage with secure BCrypt hashing

**Key Classes**:
- `PasswordService`: Handles password hashing and validation
- `PasswordMigrationService`: Migrates existing plaintext passwords

**Interface Design**:
```java
public interface PasswordService {
    String hashPassword(String plaintext);
    boolean validatePassword(String plaintext, String hash);
    boolean requiresRehashing(String hash);
}
```

**Security Features**:
- BCrypt with cost factor 12 minimum
- Password strength validation
- Secure password comparison using constant-time operations

### 2. Enhanced Authentication Service

**Purpose**: Strengthen JWT token security and validation

**Key Classes**:
- `JwtService` (enhanced): Improved token generation and validation
- `JwtAuthenticationFilter` (enhanced): Stricter token validation

**Security Enhancements**:
- Strong secret key from environment variables
- Short token lifetime (15 minutes)
- Issuer and audience claim validation
- Comprehensive signature verification

### 3. Authorization and Access Control Component

**Purpose**: Implement proper role-based access control and resource ownership validation

**Key Classes**:
- `ResourceOwnershipValidator`: Validates user ownership of resources
- `SecurityFilterChain` (enhanced): Proper endpoint protection
- `AuthorizationService`: Centralized authorization logic

**Access Control Matrix**:
- Anonymous: Only /api/auth/login, /api/auth/register
- Authenticated Users: Own resources only
- Admin Users: Administrative endpoints + own resources

### 4. Data Transfer Object (DTO) System

**Purpose**: Control data exposure and prevent mass assignment vulnerabilities

**Key Classes**:
- `UserResponseDTO`: Safe user data for responses
- `UserCreateRequestDTO`: Controlled user creation input
- `AccountResponseDTO`: Safe account data exposure
- `LoginRequestDTO`: Authentication input validation

**DTO Design Principles**:
- Separate request and response DTOs
- Exclude sensitive fields (password, role, isAdmin)
- Implement proper validation annotations
- Use mapper pattern for entity-DTO conversion

### 5. Rate Limiting Component

**Purpose**: Prevent abuse and brute-force attacks through request throttling

**Implementation Approach**:
- Use Bucket4j for sliding window rate limiting
- Different limits for different endpoint categories
- IP-based and user-based rate limiting
- Configurable rate limits through application properties

**Rate Limiting Strategy**:
- Login endpoints: 5 requests/minute per IP
- Transfer operations: 10 requests/minute per user
- General API: 100 requests/minute per user
- Admin endpoints: 20 requests/minute per admin user

### 6. Input Validation Component

**Purpose**: Comprehensive validation and sanitization of all user inputs

**Key Features**:
- Bean Validation annotations for automatic validation
- Custom validators for business logic constraints
- Range validation for numeric inputs
- String sanitization to prevent injection attacks

**Validation Rules**:
- Transfer amounts: Must be positive, within reasonable limits
- User inputs: Length limits, format validation
- Search queries: Sanitization to prevent injection
- Numeric IDs: Positive values only

### 7. Error Handling and Security Logging

**Purpose**: Secure error handling that doesn't leak sensitive information

**Key Classes**:
- `GlobalSecurityExceptionHandler`: Centralized exception handling
- `SecurityAuditService`: Security event logging
- `SecurityEventLogger`: Structured security logging

**Error Handling Strategy**:
- Generic error messages for clients
- Detailed logging server-side
- No stack trace exposure
- Security event correlation

## Data Models

### Enhanced User Model

The `AppUser` entity will be enhanced with:
- BCrypt password hashing
- Audit fields (created, modified timestamps)
- Account lockout fields for brute-force protection
- Password history for preventing reuse

### DTO Models

**UserResponseDTO**:
```java
public class UserResponseDTO {
    private Long id;
    private String username;
    private String email;
    // Excludes: password, role, isAdmin
}
```

**UserCreateRequestDTO**:
```java
public class UserCreateRequestDTO {
    @NotBlank @Size(min=3, max=50)
    private String username;
    
    @NotBlank @Size(min=8, max=100)
    private String password;
    
    @Email
    private String email;
    // Excludes: role, isAdmin (server-controlled)
}
```

### Security Configuration Model

Enhanced security configuration with:
- Environment-based JWT secret management
- Configurable rate limiting parameters
- Security policy definitions
- Audit configuration settings

## Error Handling

### Security Exception Hierarchy

1. **AuthenticationException**: Invalid credentials, expired tokens
2. **AuthorizationException**: Insufficient permissions, resource access denied
3. **ValidationException**: Invalid input data, constraint violations
4. **RateLimitException**: Rate limit exceeded
5. **SecurityConfigurationException**: Security setup issues

### Error Response Strategy

**Client Response Format**:
```json
{
    "error": "AUTHENTICATION_FAILED",
    "message": "Invalid credentials",
    "timestamp": "2024-01-01T12:00:00Z",
    "path": "/api/auth/login"
}
```

**Server-Side Logging**:
- Detailed error information with stack traces
- Security context (user, IP, endpoint)
- Correlation IDs for tracking
- Structured logging for analysis

## Testing Strategy

### Security Test Categories

1. **Authentication Tests**:
   - Password hashing validation
   - JWT token security verification
   - Authentication bypass prevention
   - Brute-force protection validation

2. **Authorization Tests**:
   - Role-based access control verification
   - Resource ownership enforcement
   - Privilege escalation prevention
   - Admin function protection

3. **Data Protection Tests**:
   - Sensitive data exposure prevention
   - Mass assignment vulnerability tests
   - DTO validation and mapping tests
   - Information leakage prevention

4. **Rate Limiting Tests**:
   - Rate limit enforcement verification
   - Different limit tier testing
   - Rate limit bypass prevention
   - Performance impact assessment

5. **Input Validation Tests**:
   - Boundary value testing
   - Injection attack prevention
   - Data type validation
   - Business rule enforcement

### Integration Test Strategy

**Test Environment Setup**:
- Isolated test database with known data
- Mock external dependencies
- Security configuration testing
- End-to-end security flow validation

**Test Data Management**:
- Secure test user creation
- Known vulnerability test cases
- Edge case scenario testing
- Performance and security benchmarking

### Vulnerability Verification Tests

Each OWASP API Top 10 vulnerability will have specific tests:

1. **API1 (BOLA)**: Resource ownership validation tests
2. **API2 (Broken Authentication)**: Authentication mechanism tests
3. **API3 (Excessive Data Exposure)**: Data filtering and DTO tests
4. **API4 (Resource Consumption)**: Rate limiting effectiveness tests
5. **API5 (Broken Function Authorization)**: Role-based access tests
6. **API6 (Mass Assignment)**: Input validation and DTO binding tests
7. **API7 (Security Misconfiguration)**: Configuration security tests
8. **API8 (Injection)**: Input sanitization and validation tests
9. **API9 (Improper Asset Management)**: API inventory and documentation tests
10. **API10 (Insufficient Logging)**: Security event logging tests

## Implementation Phases

### Phase 1: Foundation Security
- Password hashing implementation
- Basic authentication hardening
- Security configuration updates

### Phase 2: Access Control
- Authorization service implementation
- Resource ownership validation
- Role-based access control

### Phase 3: Data Protection
- DTO system implementation
- Mass assignment prevention
- Data exposure control

### Phase 4: Advanced Security
- Rate limiting implementation
- Input validation enhancement
- Error handling security

### Phase 5: Testing and Validation
- Comprehensive security test suite
- Vulnerability verification tests
- Performance and security benchmarking

## Security Considerations

### Defense in Depth

The design implements multiple security layers:
- Network security (rate limiting)
- Application security (authentication/authorization)
- Data security (encryption, hashing)
- Input security (validation, sanitization)
- Output security (DTO filtering)

### Security Monitoring

Comprehensive security event logging for:
- Authentication attempts (success/failure)
- Authorization violations
- Rate limit violations
- Input validation failures
- System security events

### Performance Impact

Security enhancements are designed with performance considerations:
- Efficient BCrypt operations with appropriate cost factors
- Optimized rate limiting with minimal overhead
- Cached authorization decisions where appropriate
- Efficient DTO mapping operations