package edu.nu.owaspapivulnlab.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.servlet.config.annotation.ContentNegotiationConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * SECURITY FIX: Web configuration for proper content negotiation
 * Ensures proper JSON handling for API endpoints
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    // SECURITY FIX: Configure proper content negotiation for JSON API
    @Override
    public void configureContentNegotiation(ContentNegotiationConfigurer configurer) {
        configurer
            .defaultContentType(MediaType.APPLICATION_JSON) // Default to JSON for API responses
            .mediaType("json", MediaType.APPLICATION_JSON);
    }
}