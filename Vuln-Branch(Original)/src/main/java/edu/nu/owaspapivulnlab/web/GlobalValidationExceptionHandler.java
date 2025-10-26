package edu.nu.owaspapivulnlab.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

/**
 * SECURITY FIX: Global exception handler for validation errors
 * FIXED: API9 Improper Assets Management - Provides secure error handling for validation failures
 */
@RestControllerAdvice
public class GlobalValidationExceptionHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(GlobalValidationExceptionHandler.class);
    
    /**
     * SECURITY FIX: Handle validation errors from DTOs
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationErrors(MethodArgumentNotValidException ex) {
        Map<String, Object> response = new HashMap<>();
        Map<String, String> errors = new HashMap<>();
        
        // SECURITY FIX: Collect all validation errors
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });
        
        response.put("error", "Validation failed");
        response.put("message", "Invalid input data provided");
        response.put("validationErrors", errors);
        response.put("timestamp", System.currentTimeMillis());
        
        // SECURITY FIX: Log validation failures for monitoring
        logger.warn("Validation failed for request: {}", errors);
        
        return ResponseEntity.badRequest().body(response);
    }
    
    /**
     * SECURITY FIX: Handle custom validation errors
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(IllegalArgumentException ex) {
        Map<String, Object> response = new HashMap<>();
        
        response.put("error", "Invalid input");
        response.put("message", ex.getMessage());
        response.put("timestamp", System.currentTimeMillis());
        
        // SECURITY FIX: Log invalid arguments for monitoring
        logger.warn("Invalid argument provided: {}", ex.getMessage());
        
        return ResponseEntity.badRequest().body(response);
    }
    
    /**
     * SECURITY FIX: Handle number format exceptions
     */
    @ExceptionHandler(NumberFormatException.class)
    public ResponseEntity<Map<String, Object>> handleNumberFormat(NumberFormatException ex) {
        Map<String, Object> response = new HashMap<>();
        
        response.put("error", "Invalid number format");
        response.put("message", "Please provide a valid number");
        response.put("timestamp", System.currentTimeMillis());
        
        // SECURITY FIX: Log number format errors for monitoring
        logger.warn("Invalid number format provided: {}", ex.getMessage());
        
        return ResponseEntity.badRequest().body(response);
    }
    
    /**
     * SECURITY FIX: Handle generic validation errors
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGenericError(Exception ex) {
        Map<String, Object> response = new HashMap<>();
        
        // SECURITY FIX: Return generic error message to prevent information leakage
        response.put("error", "Internal server error");
        response.put("message", "An unexpected error occurred");
        response.put("timestamp", System.currentTimeMillis());
        
        // SECURITY FIX: Log detailed error information server-side
        logger.error("Unexpected error occurred", ex);
        
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}
