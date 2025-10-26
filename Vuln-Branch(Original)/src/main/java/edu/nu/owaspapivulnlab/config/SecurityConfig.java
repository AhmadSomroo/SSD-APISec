package edu.nu.owaspapivulnlab.config;

import edu.nu.owaspapivulnlab.filter.RateLimitingFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.*;

import java.io.IOException;
import java.util.Collections;

@Configuration
public class SecurityConfig {

    @Value("${app.jwt.secret}")
    private String secret;
    
    @Autowired
    private RateLimitingFilter rateLimitingFilter;

    // SECURITY FIX: Hardened SecurityFilterChain configuration
    // FIXED: API7 Security Misconfiguration - Removed overly permissive endpoint access
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable()); // APIs typically stateless; but add CSRF for state-changing in real apps
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.authorizeHttpRequests(reg -> reg
                // SECURITY FIX: Only allow specific auth endpoints and user registration
                .requestMatchers("/api/auth/login", "/api/auth/register", "/h2-console/**").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/users").permitAll() // Allow user registration only
                
                // SECURITY FIX: Enforce role-based access control for admin endpoints
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                
                // SECURITY FIX: Require authentication for ALL other API endpoints
                // FIXED: Removed broad permitAll on GET /api/** that allowed data scraping
                .requestMatchers("/api/**").authenticated()
                .anyRequest().authenticated()
        );

        // SECURITY FIX: Configure proper authentication entry point to return 401 instead of 403
        // This ensures proper HTTP status codes for unauthenticated requests
        http.exceptionHandling(ex -> ex
                .authenticationEntryPoint((request, response, authException) -> {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"Unauthorized\"}");
                })
        );

        http.headers(h -> h.frameOptions(f -> f.disable())); // allow H2 console

        // SECURITY FIX: Add rate limiting filter before JWT filter
        // FIXED: API4 Lack of Resources & Rate Limiting - Prevents abuse and brute-force attacks
        http.addFilterBefore(rateLimitingFilter, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(new JwtFilter(secret), org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // SECURITY FIX: Enhanced JWT filter with comprehensive validation
    // FIXED: API8 Weak Authentication - Added issuer/audience validation and proper error handling
    static class JwtFilter extends OncePerRequestFilter {
        private final String secret;
        // SECURITY FIX: Define expected issuer and audience for JWT validation
        private static final String EXPECTED_ISSUER = "owasp-api-vuln-lab";
        private static final String EXPECTED_AUDIENCE = "api-users";
        
        JwtFilter(String secret) { this.secret = secret; }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            String auth = request.getHeader("Authorization");
            if (auth != null && auth.startsWith("Bearer ")) {
                String token = auth.substring(7);
                try {
                    // SECURITY FIX: Enhanced JWT validation with issuer and audience checks
                    // FIXED: Previous implementation had no issuer/audience validation
                    Claims c = Jwts.parserBuilder()
                            .setSigningKey(secret.getBytes())
                            .requireIssuer(EXPECTED_ISSUER)    // SECURITY FIX: Validate issuer
                            .requireAudience(EXPECTED_AUDIENCE) // SECURITY FIX: Validate audience
                            .build()
                            .parseClaimsJws(token).getBody();
                    
                    String user = c.getSubject();
                    String role = (String) c.get("role");
                    UsernamePasswordAuthenticationToken authn = new UsernamePasswordAuthenticationToken(user, null,
                            role != null ? Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role)) : Collections.emptyList());
                    SecurityContextHolder.getContext().setAuthentication(authn);
                } catch (JwtException e) {
                    // SECURITY FIX: Reject invalid tokens with proper error response
                    // FIXED: Previous implementation swallowed errors and continued as anonymous
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"Invalid or expired token\"}");
                    return;
                }
            }
            chain.doFilter(request, response);
        }
    }
}
