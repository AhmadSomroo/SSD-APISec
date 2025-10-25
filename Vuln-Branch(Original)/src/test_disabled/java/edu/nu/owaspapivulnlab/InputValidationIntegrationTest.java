package edu.nu.owaspapivulnlab;

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.nu.owaspapivulnlab.dto.AccountTransferRequestDTO;
import edu.nu.owaspapivulnlab.dto.UserCreateRequestDTO;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.HashMap;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * SECURITY FIX: Integration tests for input validation
 * FIXED: API9 Improper Assets Management - Tests comprehensive input validation across endpoints
 */
@SpringBootTest
@TestPropertySource(properties = {
    "app.jwt.secret=testSecretKeyThatIsAtLeast256BitsLongForHS256AlgorithmToWorkProperlyInProduction",
    "app.jwt.ttl-seconds=900"
})
public class InputValidationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void testTransferValidation_ValidAmount() throws Exception {
        // Test valid transfer amount
        AccountTransferRequestDTO request = new AccountTransferRequestDTO(100.50);
        
        mockMvc.perform(post("/api/accounts/1/transfer")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized()); // Expected due to authentication
    }

    @Test
    void testTransferValidation_InvalidAmount_TooHigh() throws Exception {
        // Test transfer amount exceeding maximum limit
        AccountTransferRequestDTO request = new AccountTransferRequestDTO(15000.00);
        
        mockMvc.perform(post("/api/accounts/1/transfer")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.validationErrors.amount").value("Transfer amount cannot exceed 10,000.00"));
    }

    @Test
    void testTransferValidation_InvalidAmount_TooLow() throws Exception {
        // Test transfer amount below minimum limit
        AccountTransferRequestDTO request = new AccountTransferRequestDTO(0.005);
        
        mockMvc.perform(post("/api/accounts/1/transfer")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.validationErrors.amount").value("Transfer amount must be at least 0.01"));
    }

    @Test
    void testTransferValidation_InvalidAmount_Negative() throws Exception {
        // Test negative transfer amount
        AccountTransferRequestDTO request = new AccountTransferRequestDTO(-100.0);
        
        mockMvc.perform(post("/api/accounts/1/transfer")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.validationErrors.amount").value("Transfer amount must be positive"));
    }

    @Test
    void testUserCreationValidation_ValidUser() throws Exception {
        // Test valid user creation
        UserCreateRequestDTO request = new UserCreateRequestDTO("testuser", "password123", "test@example.com");
        
        mockMvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());
    }

    @Test
    void testUserCreationValidation_InvalidUsername() throws Exception {
        // Test invalid username (too short)
        UserCreateRequestDTO request = new UserCreateRequestDTO("ab", "password123", "test@example.com");
        
        mockMvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.validationErrors.username").value("Username must be between 3 and 50 characters"));
    }

    @Test
    void testUserCreationValidation_InvalidUsername_InvalidCharacters() throws Exception {
        // Test invalid username (invalid characters)
        UserCreateRequestDTO request = new UserCreateRequestDTO("user@domain", "password123", "test@example.com");
        
        mockMvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.validationErrors.username").value("Username can only contain letters, numbers, underscores, and hyphens"));
    }

    @Test
    void testUserCreationValidation_InvalidEmail() throws Exception {
        // Test invalid email format
        UserCreateRequestDTO request = new UserCreateRequestDTO("testuser", "password123", "invalid-email");
        
        mockMvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.validationErrors.email").value("Invalid email format"));
    }

    @Test
    void testUserCreationValidation_InvalidPassword_TooShort() throws Exception {
        // Test password too short
        UserCreateRequestDTO request = new UserCreateRequestDTO("testuser", "12345", "test@example.com");
        
        mockMvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.validationErrors.password").value("Password must be between 6 and 128 characters"));
    }

    @Test
    void testUserCreationValidation_MissingFields() throws Exception {
        // Test missing required fields
        Map<String, Object> request = new HashMap<>();
        request.put("username", "testuser");
        // Missing password and email
        
        mockMvc.perform(post("/api/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.validationErrors.password").value("Password is required"))
                .andExpect(jsonPath("$.validationErrors.email").value("Email is required"));
    }

    @Test
    void testSearchValidation_ValidQuery() throws Exception {
        // Test valid search query (admin required)
        mockMvc.perform(get("/api/users/search")
                .param("q", "test query"))
                .andExpect(status().isForbidden()); // Expected due to admin requirement
    }

    @Test
    void testSearchValidation_InvalidQuery_TooLong() throws Exception {
        // Test search query too long
        String longQuery = "a".repeat(201);
        
        mockMvc.perform(get("/api/users/search")
                .param("q", longQuery))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Search query cannot exceed 200 characters"));
    }

    @Test
    void testSearchValidation_XSSAttempt() throws Exception {
        // Test XSS attempt in search query
        String maliciousQuery = "<script>alert('xss')</script>";
        
        mockMvc.perform(get("/api/users/search")
                .param("q", maliciousQuery))
                .andExpect(status().isForbidden()); // Expected due to admin requirement
    }

    @Test
    void testSearchValidation_SQLInjectionAttempt() throws Exception {
        // Test SQL injection attempt in search query
        String maliciousQuery = "'; DROP TABLE users; --";
        
        mockMvc.perform(get("/api/users/search")
                .param("q", maliciousQuery))
                .andExpect(status().isForbidden()); // Expected due to admin requirement
    }

    @Test
    void testAccountIdValidation_InvalidId() throws Exception {
        // Test invalid account ID
        AccountTransferRequestDTO request = new AccountTransferRequestDTO(100.0);
        
        mockMvc.perform(post("/api/accounts/0/transfer")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("ID must be positive"));
    }

    @Test
    void testAccountIdValidation_NegativeId() throws Exception {
        // Test negative account ID
        AccountTransferRequestDTO request = new AccountTransferRequestDTO(100.0);
        
        mockMvc.perform(post("/api/accounts/-1/transfer")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("ID must be positive"));
    }
}
